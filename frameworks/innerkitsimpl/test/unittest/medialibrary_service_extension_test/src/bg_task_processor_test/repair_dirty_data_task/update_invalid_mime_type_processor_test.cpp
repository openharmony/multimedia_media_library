/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bg_task_processor_test.h"

#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#define private public
#include "update_invalid_mime_type_processor.h"
#undef private

using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t InsertCloudAssetINDb(const string &title, const string &extension)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    string displayName = title + extension;
    string data = "/storage/cloud/files/photo/1/" + displayName;
    ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, data);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE));
    valuesBucket.PutString(PhotoColumn::MEDIA_MIME_TYPE, "application/octet-stream");
    int64_t fileId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertCloudAsset fileId is %{public}s", to_string(fileId).c_str());
    return ret;
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, update_invalid_mime_type_processor_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("update_invalid_mime_type_processor_test_001 Start");
    int32_t ret = InsertCloudAssetINDb("test1", ".jpg");
    EXPECT_EQ(ret, E_OK);
    ret = InsertCloudAssetINDb("test2", ".heic");
    EXPECT_EQ(ret, E_OK);
    ret = InsertCloudAssetINDb("test3", ".heif");
    EXPECT_EQ(ret, E_OK);
    ret = InsertCloudAssetINDb("test4", ".dng");
    EXPECT_EQ(ret, E_OK);

    auto processor = UpdateInvalidMimeTypePrecessor();
    ret = processor.UpdateInvalidMimeType();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("update_invalid_mimetype_test_001 End");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, update_invalid_mime_type_processor_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("update_invalid_mime_type_processor_test_002 Start");
    int32_t ret = InsertCloudAssetINDb("test1", ".jpg");
    EXPECT_EQ(ret, E_OK);
    ret = InsertCloudAssetINDb("test2", ".heic");
    EXPECT_EQ(ret, E_OK);
    ret = InsertCloudAssetINDb("test3", ".xxx");
    EXPECT_EQ(ret, E_OK);
    ret = InsertCloudAssetINDb("test4", ".xxx");
    EXPECT_EQ(ret, E_OK);

    auto processor = UpdateInvalidMimeTypePrecessor();
    ret = processor.UpdateInvalidMimeType();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("update_invalid_mimetype_test_002 End");
}
} // namespace Media
} // namespace OHOS
