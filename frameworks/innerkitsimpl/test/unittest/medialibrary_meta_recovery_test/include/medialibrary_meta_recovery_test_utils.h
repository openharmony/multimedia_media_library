/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_META_RECOVERY_TEST_UTILS_H
#define MEDIALIBRARY_META_RECOVERY_TEST_UTILS_H

#include <memory>
#include <vector>

#include "file_asset.h"
#include "photo_album.h"

namespace OHOS {
namespace Media {
bool CreateFile(const std::string &filePath);

void InitFileAsset(FileAsset &fileAsset);
bool CompareFileAsset(const FileAsset &fileAsset1, const FileAsset &fileAsset2);

void InitPhotoAlbum(std::vector<std::shared_ptr<PhotoAlbum>> &vecPhotoAlbum, const int32_t count);
bool ComparePhotoAlbum(const std::vector<std::shared_ptr<PhotoAlbum>> &vecPhotoAlbum1,
    const std::vector<std::shared_ptr<PhotoAlbum>> &vecPhotoAlbum2);
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_META_RECOVERY_TEST_UTILS_H