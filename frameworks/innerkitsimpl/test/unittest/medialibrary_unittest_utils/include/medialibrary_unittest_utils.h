/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_UNITTEST_UTILS_H
#define MEDIALIBRARY_UNITTEST_UTILS_H

#include "file_asset.h"

namespace OHOS {
namespace Media {
const static inline std::string TEST_CAMERA = "Camera";
const static inline std::string TEST_VIDEOS = "Videos";
const static inline std::string TEST_PICTURES = "Pictures";
const static inline std::string TEST_AUDIOS = "Audios";
const static inline std::string TEST_DOCUMENTS = "Documents";
const static inline std::string TEST_DOWNLOAD = "Download";
const static inline std::vector<std::string> TEST_ROOT_DIRS = { TEST_CAMERA, TEST_VIDEOS, TEST_PICTURES, TEST_AUDIOS,
    TEST_DOCUMENTS, TEST_DOWNLOAD };

class MediaLibraryUnitTestUtils {
public:
    MediaLibraryUnitTestUtils() {}
    virtual ~MediaLibraryUnitTestUtils() {}
    static bool IsValid();
    static void Init();
    static void InitRootDirs();
    static void CleanTestFiles();
    static std::shared_ptr<FileAsset> GetRootAsset(const std::string &dir);
    static bool IsFileExists(const std::string filePath);
    static bool GetFileAsset(const int fileId, std::shared_ptr<FileAsset> &fileAsset);
    static bool CreateAlbum(std::string displayName, std::shared_ptr<FileAsset> parentAlbumAsset,
        std::shared_ptr<FileAsset> &albumAsset);
    static bool CreateFile(std::string displayName, std::shared_ptr<FileAsset> parentAlbumAsset,
        std::shared_ptr<FileAsset> &fileAsset);
    static bool DeleteDir(const std::string &path, const std::string &dirId);
    static void TrashFile(std::shared_ptr<FileAsset> &fileAsset);
    static void RecoveryFile(std::shared_ptr<FileAsset> &fileAsset);
private:
    static inline bool isValid_ = false;
    static inline std::unordered_map<std::string, std::shared_ptr<FileAsset>> rootDirAssetMap_;
};
}
}

#endif // MEDIALIBRARY_UNITTEST_UTILS_H