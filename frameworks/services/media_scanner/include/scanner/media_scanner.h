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
#include <memory>

#include "medialibrary_type_const.h"
#include "media_scanner_const.h"
#include "media_scanner_db.h"
#include "metadata.h"
#include "metadata_extractor.h"
#include "scanner_utils.h"
#include "imedia_scanner_callback.h"
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
    MediaScannerObj(const std::string &path, const std::shared_ptr<IMediaScannerCallback> &callback, bool isDir);
    virtual ~MediaScannerObj() = default;

    void Scan();

    /* stop */
    void SetStopFlag(std::shared_ptr<bool> &stopFlag);

private:
    /* file */
    int32_t ScanFile();
    int32_t ScanFileInternal();
    int32_t GetFileMetadata();
    int32_t GetParentDirInfo(const std::string &parent, int32_t parentId);
    int32_t GetMediaInfo();

    /* dir */
    int32_t ScanDir();
    int32_t ScanDirInternal();
    int32_t ScanFileInTraversal(const std::string &path, const std::string &parent, int32_t parentId);
    int32_t WalkFileTree(const std::string &path, int32_t parentId);
    int32_t CleanupDirectory();
    int32_t InsertOrUpdateAlbumInfo(const std::string &albumPath, int32_t parentId, const std::string &albumName);

    /* db ops */
    int32_t Commit();
    int32_t AddToTransaction();
    int32_t CommitTransaction();

    /* callback */
    int32_t InvokeCallback(int32_t code);

    std::string path_;
    std::string dir_;
    bool isDir_;
    std::string uri_;
    std::unique_ptr<MediaScannerDb> mediaScannerDb_;
    const std::shared_ptr<IMediaScannerCallback> callback_;
    std::shared_ptr<bool> stopFlag_;

    std::unique_ptr<Metadata> data_;
    std::unordered_map<std::string, Metadata> albumMap_;
    std::unordered_set<int32_t> scannedIds_;
    std::vector<std::unique_ptr<Metadata>> dataBuffer_;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIA_SCANNER_OBJ_H
