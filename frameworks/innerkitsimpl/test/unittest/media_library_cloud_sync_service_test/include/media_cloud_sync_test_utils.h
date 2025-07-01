/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLOUD_SYNC_TEST_UTILS_H
#define OHOS_MEDIA_CLOUD_SYNC_TEST_UTILS_H

#include <memory>
#include <string>
#include "medialibrary_rdbstore.h"

namespace OHOS::Media::CloudSync {
struct UniqueMemberValuesBucket {
    std::string assetMediaType;
    int32_t startNumber;
};

void CleanTestTables(std::shared_ptr<MediaLibraryRdbStore> rdbStore);
void SetTestTables(std::shared_ptr<MediaLibraryRdbStore> rdbStore);
void InitTestTables(std::shared_ptr<MediaLibraryRdbStore> rdbStore);
void PrepareUniqueNumberTable(std::shared_ptr<MediaLibraryRdbStore> rdbStore);
void ClearAndRestart(std::shared_ptr<MediaLibraryRdbStore> rdbStore);

void SetValuesBucketInPhotosTable(const std::string &columnKey, const std::string &columnValue,
    OHOS::NativeRdb::ValuesBucket &values);
void SetValuesBucketInPhotoAlbumTable(const std::string &columnKey, const std::string &columnValue,
    OHOS::NativeRdb::ValuesBucket &values);

void InitPhotosTable(std::shared_ptr<MediaLibraryRdbStore> rdbStore);
void InitPhotoAlbumTable(std::shared_ptr<MediaLibraryRdbStore> rdbStore);

int32_t InsertTable(std::shared_ptr<MediaLibraryRdbStore> rdbStore, const std::string &tableName,
    OHOS::NativeRdb::ValuesBucket &values);
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_TEST_UTILS_H