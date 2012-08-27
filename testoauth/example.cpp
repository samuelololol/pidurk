/*  Copyright 2008,2009,2010 Edwin Eefting (edwin@datux.nl) 

    This file is part of Synapse.

    Synapse is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Synapse is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Synapse.  If not, see <http://www.gnu.org/licenses/>. */


#include "synapse.h"
#include "cconfig.h"
#include "clog.h"
#include <map>
#include <string>
#include <deque>

#include "exception/cexception.h"

//include curl_ssl_lock to initalise correct thread locking for the ssl libraries
#define USE_OPENSSL
#include <curl/curl.h>
#include "curl_ssl_lock.hpp"

#include <boost/thread/thread.hpp>
#include <boost/shared_ptr.hpp>

//oauth support is optional!
#ifdef OAUTH
extern "C" {
#include <oauth.h>
}
#endif

namespace synapse_curl
{

using namespace std;
using namespace boost;

synapse::Cconfig config;

//A curl instance
class Ccurl
{
	private:
	//threading stuff
	shared_ptr<mutex> mMutex;
	shared_ptr<condition_variable> mQueueChanged;

	//Ccurl stuff:
	bool mAbort;		//try to abort this transfer
	bool mPerforming; 	//we have assigned a performer
	typedef deque<Cmsg> Cqueue;
	Cqueue mQueue;	//queue with operations to perform

	//libcurl stuff:
	CURL *mCurl;
	char mError[CURL_ERROR_SIZE];

	public:
	Cqueue::iterator mMsg; //current message being handled

	Ccurl()
	{
		mAbort=false;
		mPerforming=false;
		mMutex=shared_ptr<mutex>(new mutex);
		mQueueChanged=shared_ptr<condition_variable>(new condition_variable);

		mCurl=curl_easy_init();
		if (!mCurl)
			throw(synapse::runtime_error("Error creating new curl instance"));

	}

	//aborts all downloads and empties queue
	void abort()
	{
		lock_guard<mutex> lock(*mMutex);
		mAbort=true;
		mQueue.empty();
		mQueueChanged->notify_one();
	}

	//enqueues a download. returns true if the calling thread should call perform().
	bool enqueue(Cmsg & msg)
	{
		lock_guard<mutex> lock(*mMutex);

		//create new queue message
		Cmsg queueMsg;
		queueMsg=msg;
		queueMsg.dst=msg.src;
		queueMsg.src=0;
//		queueMsg["id"]=msg["id"];
//		queueMsg["url"]=msg["url"];
//		queueMsg["httpauth"]=msg["httpauth"];
//		queueMsg["username"]=msg["username"];
//		queueMsg["password"]=msg["password"];
		mQueue.push_back(queueMsg);

		Cqueue::iterator lastMsg=(--mQueue.end());

		mQueueChanged->notify_one();

		//no performing thread yet?
		if (!mPerforming)
		{
			mPerforming=true;
			return(true);
		}

		return(false);
	}

	//returns true if perform() should be called again
	//only call this when not already performing. when it returns false , curl is uninitalized so dont call perform or anything else again.
	bool shouldPerform()
	{
		lock_guard<mutex> lock(*mMutex);


		//still no data after waiting, delete curl instance and make sure we dont get called again
		if (mQueue.empty())
		{
			DEB("Queue empty, cleaning up curl instance")
			curl_easy_reset(mCurl); //make sure the callbacks aren't called anymore!
			curl_easy_cleanup(mCurl);
			return (false);
		}
		else
		{
			return(true);
		}
	}

	static int curl_debug_callback (CURL * curl, curl_infotype type, char * data, size_t length, Ccurl *curlObj)
	{
		if (type==CURLINFO_TEXT)
		{
			string text;
			text.resize(length);
			memcpy((void *)text.c_str(),data,length);
			text.erase(--text.end());
			INFO("curl (" <<
					curlObj->mMsg->dst << " "  <<
					(*curlObj->mMsg)["id"].str() << ") " << text);
		}

		return 0;
	}

	static size_t curl_write_callback( void *data, size_t size, size_t nmemb, Ccurl *curlObj)
	{
		(*curlObj->mMsg)["data"].str().resize(size*nmemb);
		memcpy( (void *)(*curlObj->mMsg)["data"].str().c_str(), data,size*nmemb);
		curlObj->mMsg->event="curl_Data";
		curlObj->mMsg->send();
		curlObj->mMsg->erase("data");
		return (size*nmemb);
	}

	//only one thread may call perform at a time: this is indicated with enqueue() returning true
	//as long as shouldPerform() returns true you should recall this function, without any locking at all.
	//(the other public functions are threadsafe)
	void perform()
	{
		CURLcode err;
		struct curl_slist *headers=NULL;

		{
			unique_lock<mutex> lock(*mMutex);

			//empty?
			if (mQueue.empty())
				return;

			//activate message
			mMsg=mQueue.begin();

			//set curl options, as long as there are no errors
			curl_easy_reset(mCurl);
			(err=curl_easy_setopt(mCurl, CURLOPT_NOSIGNAL, 1))==0 &&
			(err=curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, curl_write_callback))==0 &&
			(err=curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, this))==0 &&
			(err=curl_easy_setopt(mCurl, CURLOPT_DEBUGFUNCTION, curl_debug_callback))==0 &&
			(err=curl_easy_setopt(mCurl, CURLOPT_DEBUGDATA, this))==0 &&
			(err=curl_easy_setopt(mCurl, CURLOPT_ERRORBUFFER , &mError))==0 &&
			(err=curl_easy_setopt(mCurl, CURLOPT_URL, (*mMsg)["url"].str().c_str() ))==0 &&
			(err=curl_easy_setopt(mCurl, CURLOPT_VERBOSE, (int)config["verbose"]))==0;

			//authorisation
			if (err==0 && mMsg->isSet("username"))
				err=curl_easy_setopt(mCurl, CURLOPT_USERNAME, (*mMsg)["username"].str().c_str() );

			if (err==0 && mMsg->isSet("password"))
				err=curl_easy_setopt(mCurl, CURLOPT_PASSWORD, (*mMsg)["password"].str().c_str() );

			if (err==0 && mMsg->isSet("httpauth"))
			{
				if ((*mMsg)["httpauth"].str()=="basic")
					err=curl_easy_setopt(mCurl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
				else if ((*mMsg)["httpauth"].str()=="digest")
					err=curl_easy_setopt(mCurl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
				else if ((*mMsg)["httpauth"].str()=="any")
					err=curl_easy_setopt(mCurl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
			}

			if (err==0)
			{
				//NOTE: we default to failonerror=1, while libcurl normally defaults to 0
				if ((*mMsg).isSet("failonerror"))
					err=curl_easy_setopt(mCurl, CURLOPT_FAILONERROR, (int)(*mMsg)["failonerror"]);
				else
					err=curl_easy_setopt(mCurl, CURLOPT_FAILONERROR, 1);
			}

			if (err==0 && mMsg->isSet("post"))
			{
				(err=curl_easy_setopt(mCurl, CURLOPT_POST, 1))==0 &&
				(err=curl_easy_setopt(mCurl, CURLOPT_POSTFIELDS, ((*mMsg)["post"].str().c_str())))==0 &&
				(err=curl_easy_setopt(mCurl, CURLOPT_POSTFIELDSIZE, ((*mMsg)["post"].str().length())))==0;
			}

#ifdef OAUTH
			//oauth autorisation (optionally compiled in)
			if (mMsg->isSet("oauth"))
			{
				//WARNING: convert all used parameters to strings already so we dont throw errors later on and leak mem.
				for(Cvar::iterator I=(*mMsg)["oauth"].begin(); I!=(*mMsg)["oauth"].end(); I++)
				{
					I->second.str();
				}

                // samuel, POST METHOD
				if ((*mMsg).isSet("post"))
					(*mMsg)["post"].str();

				(*mMsg)["url"].str();

				//now collect base-uri, GET , POST and extra oauth_... parameters in a liboauth-array
                // samuel,                    ### .... extra oauth_... parameters ...###
                //
                // samuel, argc/argv now is from here!
                // samuel, first step: oauth_split_url_parameters()
				int  argc;
				char **argv = NULL;
				argc = oauth_split_url_parameters((*mMsg)["url"].str().c_str(), &argv);
				if ((*mMsg).isSet("post"))
					argc = oauth_split_post_paramters((*mMsg)["post"].str().c_str(), &argv, 1);

                // samuel, there is no callback right now
				if ((*mMsg)["oauth"].isSet("callback"))
				{
					string s="oauth_callback="+(*mMsg)["oauth"]["callback"].str();
					oauth_add_param_to_array(&argc, &argv, s.c_str());
				}
                
                // samuel, we do have verifier
				if ((*mMsg)["oauth"].isSet("verifier"))
				{
                    // string will be the following 
					string s="oauth_verifier="+(*mMsg)["oauth"]["verifier"].str();
                    // samuel, second step: oauth_add_param_to_array()
					oauth_add_param_to_array(&argc, &argv, s.c_str());
				}

				const char *oauth_token=NULL;
				const char *oauth_token_secret=NULL;
				if ((*mMsg)["oauth"].isSet("token"))
				{
                    // samuel, third step: get token
					oauth_token=(*mMsg)["oauth"]["token"].str().c_str();
					oauth_token_secret=(*mMsg)["oauth"]["token_secret"].str().c_str();
				}

                // samuel, forth step: sign all info in it
				//sign it
				oauth_sign_array2_process(
						&argc,
						&argv,
						NULL, //< postargs (unused)
						OA_HMAC,
						(*mMsg).isSet("post")?"POST":"GET",
						(*mMsg)["oauth"]["consumer_key"].str().c_str(),
						(*mMsg)["oauth"]["consumer_key_secret"].str().c_str(),
						oauth_token,
						oauth_token_secret
					);


                // samuel, fifth step: create header: oauth_serialize_url_sep()
				// we split off the oauth_... parameters (for use in HTTP Authorization header)
				char *oauth_hdr = NULL;
				oauth_hdr = oauth_serialize_url_sep(argc, 1, argv, (char *)", ", 6);

				//format header and add to curl
				string authHeader="Authorization: OAuth ";
				authHeader+=oauth_hdr;
				DEB("oauth header: " << authHeader);
				headers = curl_slist_append(headers, authHeader.c_str());

				//free oauth stuff again
				oauth_free_array(&argc, &argv);
				if (oauth_hdr!=NULL)
					free(oauth_hdr);

			}

#else
			err=CURLE_HTTP_POST_ERROR;
			strcpy(mError,"Oauth support not compiled in. (please get liboauth and recompile synapse)");
#endif


			//there are headers defined?
			if (err==0 && headers!=NULL)
				(err=curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, headers));

			//indicate start
			mMsg->event="curl_Start";
			mMsg->send();
		}

		//perform the operation (unlocked)
		if (err==0)
		{
			err=curl_easy_perform(mCurl);
		}

		{
			unique_lock<mutex> lock(*mMutex);

			if (err==0)
			{
				//ok, indicate done
				mMsg->event="curl_Ok";
				long response=0;
				if (curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &response)==0)
				{
					(*mMsg)["response"]=response;
				}
				mMsg->send();
				mMsg->erase("response");
			}
			else
			{
				//error, indicate error
				mMsg->event="curl_Error";
				(*mMsg)["error"]=mError;
				mMsg->send();
			}

			//free headers
			if (headers!=NULL)
				curl_slist_free_all(headers);

			//remove from queue
			mQueue.pop_front();

			//queue is now empty? wait a while for new messages to be queued
			//(curl keeps connections open and remembers cookies and stuff.)
			if (mQueue.empty())
			{
				//wait until someone throws something in the queue
				DEB("Queue empty, waiting...");
				if (mQueueChanged->timed_wait(lock, posix_time::seconds(10)))
					DEB("Queue filled again, continueing")
				else
					DEB("Queue wait timeout");
			}

		}
	}
};


mutex curlMapMutex;
typedef pair<int, string> CcurlKey;
typedef map<CcurlKey, Ccurl> CcurlMap;
CcurlMap curlMap;
int defaultSession;



SYNAPSE_REGISTER(module_Init)
{
	Cmsg out;

	defaultSession=dst;

	//load config file
	config.load("etc/synapse/curl.conf");

	init_locks();
	if (curl_global_init(CURL_GLOBAL_ALL)!=0)
		throw(synapse::runtime_error("Error while initializing curl"));

	out.clear();
	out.event="core_ChangeModule";
	out["maxThreads"]=config["maxProcesses"];
	out.send();

	out.clear();
	out.event="core_ChangeSession";
	out["maxThreads"]=config["maxProcesses"];
	out.send();

	out.clear();
	out.event="core_Ready";
	out.send();
}

SYNAPSE_REGISTER(module_Shutdown)
{
	curl_global_cleanup();
	kill_locks();
}


Ccurl & getCurl(int src, string & id)
{
	if (curlMap.find(CcurlKey(src,id))==curlMap.end())
		throw(synapse::runtime_error("Download id not found"));

	return(curlMap.find(CcurlKey(src,id))->second);
}

/** Get specified url
Downloads the specified url.

	\param id uniq identifier to reconginise the download. multiple downloads with the same ID from the same source session will be queued.
	\param url The url to download
	\param httpauth HTTP authentication method (basic, digest, any)
	\param username
	\param password
	\param failonerror Set to 0 to NOT fail on an HTTP error response codes. this way you can receive usefull error messages in the http response body.
	\param post If set, issues a HTTP POST. The data string will be posted using the application/x-www-form-urlencoded type. (e.g. you need to encode the data yourself)
	\param oauth Contains oauth parameters. (look at the examples like twitter, too complex to explain here)

\par Replys:
	In every reply all the parameters used in the curl_Get are returned.

	curl_Start	Indicates start of download
	curl_Data	Sended for received data. \param data will contain the data.
	curl_Ok		Indicates downloading is ready
	curl_Error  Indicates downloading is aborted. \param error contains error description.
 */
SYNAPSE_REGISTER(curl_Get)
{
	CcurlKey key(msg.src, msg["id"]);
	CcurlMap::iterator curlI=curlMap.end();
	bool perform=true;

	{
		lock_guard<mutex> lock(curlMapMutex);

		//returns true if we should call perform
		perform=curlMap[key].enqueue(msg);

		curlI=curlMap.find(key);
	}

	//loop while we should perform downloads
	while (perform)
	{
		//call it unlocked! (since this is the thing that takes a long time)
		curlI->second.perform();

		{
			lock_guard<mutex> lock(curlMapMutex);

			//we need this construction to prevent the racecondition when something is enqueued just after perform has returned
			if (!curlI->second.shouldPerform())
			{
				//delete it
				curlMap.erase(curlI);
				perform=false;
			}
		}
	}
}


SYNAPSE_REGISTER(curl_Abort)
{
	lock_guard<mutex> lock(curlMapMutex);
	getCurl(msg.src,msg["id"]).abort();
}



//end namespace
}
