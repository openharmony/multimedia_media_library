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

#ifndef MEDIA_SCANNER_OBJ_H
#define MEDIA_SCANNER_OBJ_H

#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <ftw.h>
#include <iostream>
#include <iterator>
#include <limits.h>
#include <securec.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "medialibrary_type_const.h"
#include "media_scanner_const.h"
#include "media_scanner_db.h"
#include "metadata.h"
#include "metadata_extractor.h"
#include "scanner_utils.h"
#include "imedia_scanner_operation_callback.h"
#include "iremote_object.h"

#define FREE_MEMORY_AND_SET_NULL(fName)      \
    do {                                     \
        free(fName);                         \
        fName = nullptr;                     \
    } while (0)

namespace OHOS {
namespace Media {
/**
 * Media Scanner class for scanning files and folders in MediaLibrary Database
 * and updating the metadata for each media file
 *
 * @since 1.0
 * @version 1.0
 */
class MediaScannerObj {
public:
    MediaScannerObj(std::string &path, const sptr<IRemoteObject> &callback, bool isDir) : path_(path),
        callback_(callback), isDir_(isDir) {}
    virtual ~MediaScannerObj() = default;

    int32_t ScanFile();
    int32_t ScanDir();

    bool isDir();

private:
    void InitSkipList();
    void CheckIfFolderScanCompleted(const int32_t reqId);
    void CleanupDirectory(const std::string &path);

    bool CheckSkipScanList(const std::string &path);
    bool IsDirHidden(const std::string &path);
    bool IsDirHiddenRecursive(const std::string &path);

    int32_t VisitFile(const Metadata &fileMetadata);
    int32_t WalkFileTree(const std::string &path, int32_t parentId);

    int32_t InsertAlbumInfo(std::string &albumPath, int32_t parentId, string albumName);

    int32_t ScanFileInternal();
    int32_t ScanDirInternal();

    int32_t InvokeCallback(int32_t code);
    int32_t GetFileMetadata();
    int32_t GetParentDirInfo(string &path);
    int32_t GetMediaInfo();

    int32_t AddToTransaction();
    int32_t CommitTransaction();

    std::unordered_map<std::string, Metadata> albumMap_;

    std::vector<size_t> skipList_;
    std::unordered_set<int32_t> scannedIds_;
    std::vector<Metadata> batchUpdate_;
    std::unique_ptr<MediaScannerDb> mediaScannerDb_;
    std::unordered_map<int32_t, sptr<IMediaScannerOperationCallback>> scanResultCbMap_;

    std::string path_;
    std::string uri_;
    const sptr<IRemoteObject> callback_;
    bool isDir_;

    unique_ptr<Metadata> data_;
    std::vector<unique_ptr<Metadata>> dataBuffer_;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIA_SCANNER_OBJ_H
