/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define MLOG_TAG "Scanner"

#include "scanner_utils.h"

#include <cerrno>
#include <fstream>

#include "directory_ex.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace std;

std::vector<size_t> ScannerUtils::skipList_;

// Check if file exists or not
bool ScannerUtils::IsExists(const string &path)
{
    struct stat statInfo {};

    if (path.empty()) {
        MEDIA_ERR_LOG("Given path name is empty");
        return false;
    }

    return ((stat(path.c_str(), &statInfo)) == ERR_SUCCESS);
}

// Get the file name from file URI
string ScannerUtils::GetFileNameFromUri(const string &path)
{
    if (!path.empty()) {
        size_t lastSlashPosition = path.rfind("/");
        if (lastSlashPosition != string::npos) {
            if (path.size() > lastSlashPosition) {
                return path.substr(lastSlashPosition + 1);
            }
        }
    }

    MEDIA_ERR_LOG("Failed to obtain file name because given pathname is empty");
    return "";
}

// Get file extension from the given filepath uri
string ScannerUtils::GetFileExtension(const string &path)
{
    if (!path.empty()) {
        size_t dotIndex = path.rfind(".");
        if (dotIndex != string::npos) {
            return path.substr(dotIndex + 1);
        }
    }

    MEDIA_ERR_LOG("Failed to obtain file extension because given pathname is empty");
    return "";
}

// Check if the given path is a directory path
bool ScannerUtils::IsDirectory(const string &path)
{
    struct stat s;

    if (!path.empty()) {
        if (stat(path.c_str(), &s) == 0) {
            if (s.st_mode & S_IFDIR) {
                return true;
            }
        }
    }

    MEDIA_ERR_LOG("Either path is empty or it is not a directory");
    return false;
}

bool ScannerUtils::IsRegularFile(const string &path)
{
    struct stat s;
    if (!path.empty()) {
        if (stat(path.c_str(), &s) == 0) {
            if (s.st_mode & S_IFREG) {
                return true;
            }
        }
    }

    return false;
}

// Check if the given file starts with '.' , i.e. if it is hidden
bool ScannerUtils::IsFileHidden(const string &path)
{
    if (!path.empty()) {
        string fileName = GetFileNameFromUri(path);
        if (!fileName.empty() && fileName.at(0) == '.') {
            return true;
        }
    }

    MEDIA_ERR_LOG("Either filepath is empty or it is not hidden");
    return false;
}

// Get the parent path
string ScannerUtils::GetParentPath(const string &path)
{
    if (!path.empty()) {
        size_t lastSlashPosition = path.rfind("/");
        if (lastSlashPosition != string::npos && path.size() > lastSlashPosition) {
            return path.substr(0, lastSlashPosition);
        }
    }

    MEDIA_ERR_LOG("Failed to obtain the parent path");
    return "";
}

void ScannerUtils::GetRootMediaDir(string &dir)
{
    dir = ROOT_MEDIA_DIR;
}

string ScannerUtils::GetFileTitle(const string &displayName)
{
    string::size_type pos = displayName.find_last_of('.');
    return (pos == string::npos) ? displayName : displayName.substr(0, pos);
}

bool ScannerUtils::IsDirHidden(const string &path)
{
    bool dirHid = false;

    if (!path.empty()) {
        string dirName = ScannerUtils::GetFileNameFromUri(path);
        if (!dirName.empty() && dirName.at(0) == '.') {
            MEDIA_ERR_LOG("Directory is of hidden type");
            return true;
        }

        string curPath = path;
        string excludePath = curPath.append("/.nomedia");
        // Check is the folder consist of .nomedia file
        if (ScannerUtils::IsExists(excludePath)) {
            return true;
        }

        // Check is the dir is part of skiplist
        if (CheckSkipScanList(path)) {
            return true;
        }
    }

    return dirHid;
}

bool ScannerUtils::IsDirHiddenRecursive(const string &path)
{
    bool dirHid = false;
    string curPath = path;

    do {
        dirHid = IsDirHidden(curPath);
        if (dirHid) {
            break;
        }

        curPath = ScannerUtils::GetParentPath(curPath);
        if (curPath.empty()) {
            break;
        }
    } while (true);

    return dirHid;
}

// Initialize the skip list
void ScannerUtils::InitSkipList()
{
    hash<string> hashStr;
    size_t hashPath;
    string path;

    /*
     * 1. file path: in disk or hard code? path?
     * 2. call_once: no need to init again if it is really empty
     * 3. add lock
     */
    ifstream skipFile(SKIPLIST_FILE_PATH.c_str());
    if (skipFile.is_open()) {
        while (getline(skipFile, path)) {
            hashPath = hashStr(path);
            skipList_.insert(skipList_.begin(), hashPath);
        }
        skipFile.close();
    }

    return;
}

// Check if path is part of Skip scan list
bool ScannerUtils::CheckSkipScanList(const string &path)
{
    hash<string> hashStr;
    size_t hashPath;

    if (skipList_.empty()) {
        InitSkipList();
    }

    hashPath = hashStr(path);
    if (find(skipList_.begin(), skipList_.end(), hashPath) != skipList_.end()) {
        return true;
    }

    return false;
}
} // namespace Media
} // namespace OHOS
