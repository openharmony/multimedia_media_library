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

#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "values_bucket.h"
#include "rdb_utils.h"
#include "parameters.h"
#include "preferences.h"
#include "preferences_helper.h"

#define private public
#include "repair_no_origin_photo_processor.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const int32_t SCANLINE_DEFAULT_VERSION = 0;
const int32_t SCANLINE_CURRENT_VERSION = 1;
const int32_t VISIT_TIME = 2;
const int32_t THUMBNAIL_READY = 3;
const int32_t DIRTY_TYPE = 100;
const int64_t MEIDA_SIZE_VALUE = 6837689;

const std::string SCANLINE_VERSION = "scanline_version";
const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
const std::string PHOTO_DIR = "/storage/cloud/files/Photo/16/";
const std::string PHOTO_PATH = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
const std::string THUMB_DIR = "/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/";
const std::string THB_PATH = "/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/THM.jpg";
const std::string LCD_PATH = "/storage/cloud/files/.thumbs/Photo/16/IMG_1501924305_000.jpg/LCD.jpg";

int32_t InsertThumbAsset(int32_t count, int32_t &fileId)
{
    MEDIA_INFO_LOG("start");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_LCD_VISIT_TIME, VISIT_TIME);
    value.Put(PhotoColumn::PHOTO_THUMBNAIL_READY, THUMBNAIL_READY);
    value.Put(PhotoColumn::PHOTO_DIRTY, DIRTY_TYPE);
    value.Put(MediaColumn::MEDIA_FILE_PATH, PHOTO_PATH);
    value.Put(MediaColumn::MEDIA_SIZE, MEIDA_SIZE_VALUE);
    value.Put(PhotoColumn::PHOTO_SUBTYPE, 0);
    value.Put(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, 0);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::PHOTOS_TABLE, insertValues);
    EXPECT_EQ(ret, E_OK);
    fileId = static_cast<int32_t>(outRowId);
    MEDIA_INFO_LOG("InsertOldAsset end, fileId: %{public}d", fileId);
    return E_OK;
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, RepairNoOriginPhoto_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairNoOriginPhoto_test_001 start");
    int32_t errCode;
    std::shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    prefs->PutInt(SCANLINE_VERSION, SCANLINE_DEFAULT_VERSION);
    EXPECT_EQ(prefs->GetInt(SCANLINE_VERSION, SCANLINE_DEFAULT_VERSION), SCANLINE_DEFAULT_VERSION);
    auto processor = RepairNoOriginPhotoPrecessor();
    processor.RepairNoOriginPhoto();
    prefs->PutInt(SCANLINE_VERSION, SCANLINE_CURRENT_VERSION);
    prefs->FlushSync();
    EXPECT_EQ(prefs->GetInt(SCANLINE_VERSION, SCANLINE_DEFAULT_VERSION), SCANLINE_CURRENT_VERSION);
    processor.RepairNoOriginPhoto();
    MEDIA_INFO_LOG("RepairNoOriginPhoto_test_001 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, HandleNoOriginPhoto_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HandleNoOriginPhoto_test_001 start");
    int32_t fileId = -1;
    int32_t ret = InsertThumbAsset(1, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预置缩略图，效果图不存在
    MediaFileUtils::CreateDirectory(PHOTO_DIR);
    MediaFileUtils::CreateDirectory(THUMB_DIR);
    MediaFileUtils::DeleteFile(PHOTO_PATH);
    MediaFileUtils::CreateFile(THB_PATH);
    MediaFileUtils::CreateFile(LCD_PATH);
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_PATH), false);
    auto processor = RepairNoOriginPhotoPrecessor();
    processor.HandleNoOriginPhoto();
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_PATH), true);
    MEDIA_INFO_LOG("HandleNoOriginPhoto_test_001 end");
}

} // namespace Media
} // namespace OHOS
