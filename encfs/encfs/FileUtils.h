/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 * 
 * This program is free software; you can distribute it and/or modify it under 
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
                             
#ifndef _FileUtils_incl_
#define _FileUtils_incl_

#include "encfs.h"
#include "Interface.h"
#include "CipherKey.h"
#include "FSConfig.h"

#include <map>
#include <string>

using namespace std;

// true if the path points to an existing node (of any type)
bool fileExists( const char *fileName );
// true if path is a directory
bool isDirectory( const char *fileName );
// true if starts with '/'
bool isAbsolutePath( const char *fileName );
// pointer to just after the last '/'
const char *lastPathElement( const char *name );

std::string parentDirectory( const std::string &path );

// ask the user for permission to create the directory.  If they say ok, then
// do it and return true.
bool userAllowMkdir( const char *dirPath, mode_t mode );

class Cipher;
class DirNode;

struct EncFS_Root
{
    boost::shared_ptr<Cipher> cipher;
    CipherKey volumeKey;
    boost::shared_ptr<DirNode> root;

    EncFS_Root();
    ~EncFS_Root();
};

typedef boost::shared_ptr<EncFS_Root> RootPtr;

enum ConfigMode
{
    Config_Prompt,
    Config_Standard,
    Config_Paranoia
};

struct EncFS_Opts
{
    std::string rootDir;
    bool createIfNotFound;  // create filesystem if not found
    bool idleTracking; // turn on idle monitoring of filesystem
    bool mountOnDemand; // mounting on-demand

    bool checkKey;  // check crypto key decoding
    bool forceDecode; // force decode on MAC block failures

    std::string passwordProgram; // path to password program (or empty)
    bool useStdin; // read password from stdin rather then prompting

    bool ownerCreate; // set owner of new files to caller

    bool reverseEncryption; // Reverse encryption

    ConfigMode configMode;

    EncFS_Opts()
    {
        createIfNotFound = true;
        idleTracking = false;
        mountOnDemand = false;
        checkKey = true;
        forceDecode = false;
        useStdin = false;
        ownerCreate = false;
        reverseEncryption = false;
        configMode = Config_Prompt;
    }
};

/*
    Read existing config file.  Looks for any supported configuration version.
*/
ConfigType readConfig( const std::string &rootDir, 
        const boost::shared_ptr<EncFSConfig> &config ); 

/*
    Save the configuration.  Saves back as the same configuration type as was
    read from.
*/
bool saveConfig( ConfigType type, const std::string &rootdir, 
	const boost::shared_ptr<EncFSConfig> &config );

class EncFS_Context;

RootPtr initFS( EncFS_Context *ctx, const boost::shared_ptr<EncFS_Opts> &opts );

RootPtr createV6Config( EncFS_Context *ctx, 
                        const boost::shared_ptr<EncFS_Opts> &opts );

void showFSInfo( const boost::shared_ptr<EncFSConfig> &config );

bool readV4Config( const char *configFile, 
        const boost::shared_ptr<EncFSConfig> &config,
	struct ConfigInfo *);
bool writeV4Config( const char *configFile, 
        const boost::shared_ptr<EncFSConfig> &config);

bool readV5Config( const char *configFile, 
        const boost::shared_ptr<EncFSConfig> &config,
	struct ConfigInfo *);
bool writeV5Config( const char *configFile, 
        const boost::shared_ptr<EncFSConfig> &config);

bool readV6Config( const char *configFile, 
        const boost::shared_ptr<EncFSConfig> &config,
	struct ConfigInfo *);
bool writeV6Config( const char *configFile, 
        const boost::shared_ptr<EncFSConfig> &config);

bool createConfig(const std::string& rootDir, bool paranoid, bool reverse_compat, const char* password, bool throw_on_error);

bool normalize_stdin_str(char* str);
bool get_str_pair(char* str_key, char** val);

typedef std::map<string, string> string_map;
bool read_stdin(string_map& map);

template<class T> void normalize_dir_path(T& path)
{
	if (path.empty())
		return;

	auto ch = path.at(path.length() - 1);
	if (ch != '\\' && ch != '/')
		path += '\\';
}

wstring get_current_path();

wstring codepage_to_wstr(const string& str, unsigned int codepage);
wstring utf8_to_wstr(const string& str);

string wstr_to_codepage(const wstring& wstr, unsigned int codepage);
string wstr_to_utf8(const wstring& wstr);

string utf8_to_codepage(const string& str, unsigned int codepage);
string codepage_to_utf8(const string& str, unsigned int codepage);

template<class T> bool try_get_map_val(const std::map<T, T> & map, const T& key, T* val = 0)
{
	std::map<T, T>::const_iterator it = map.find(key);
	if (it == map.end())
		return false;

	if (val)
		*val = it->second;

	return true;
}

template<class T, typename T2> bool try_get_map_val(const std::map<T, T> & map, const T2* key, T* val = 0)
{
	T tkey;
	if (key)
		tkey = key;

	return try_get_map_val(map, tkey, val);
}

template<class T> T get_map_val(const std::map<T, T> & map, const T& key, const T& def_val = T())
{
	T val;
	if (!try_get_map_val(map, key, &val))
		return def_val;

	return val;
}

template<class T, typename T2> T get_map_val(const std::map<T, T> & map, const T2* key, const T2* def_val = 0)
{
	T tkey;
	if (key)
		tkey = key;

	T tdef_val;
	if (def_val)
		tdef_val = def_val;

	return get_map_val(map, tkey, tdef_val);
}

bool decode_config(const string& str, bool& paranoid, bool& reverse_compat);

#endif
