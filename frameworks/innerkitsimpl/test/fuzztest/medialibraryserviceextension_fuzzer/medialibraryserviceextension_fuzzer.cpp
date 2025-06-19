/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "medialibraryserviceextension_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "repair_no_origin_photo_processor.h"
#undef private
#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
static const string PHOTOS_TABLE = "Photos";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider *FDP = nullptr;
static const int32_t NUM_BYTES = 1;
static const int32_t VARIABLE_INT32_COUNT = 2;
static const int8_t VARIABLE_BOOL_COUNT = 1;
static const int8_t VARIABLE_STRING_COUNT = 1;
static const int MIN_SIZE = sizeof(int32_t) * VARIABLE_INT32_COUNT + sizeof(int64_t) +
    sizeof(int8_t) * (VARIABLE_BOOL_COUNT + VARIABLE_STRING_COUNT);

static inline int32_t FuzzPhotoSubType()
{
    int32_t value = FDP->ConsumeIntegral<int32_t>() % 8;
    if (value >= static_cast<int32_t>(Media::PhotoSubType::DEFAULT) &&
        value <= static_cast<int32_t>(Media::PhotoSubType::SUBTYPE_END)) {
        return value;
    }
    return static_cast<int32_t>(Media::PhotoSubType::MOVING_PHOTO);
}
 
static inline int32_t FuzzMovingPhotoEffectMode()
{
    int32_t value = FDP->ConsumeIntegral<int32_t>() % 10;
    if (value >= static_cast<int32_t>(Media::MovingPhotoEffectMode::EFFECT_MODE_START) &&
        value <= static_cast<int32_t>(Media::MovingPhotoEffectMode::IMAGE_ONLY)) {
        return value;
    }
    return static_cast<int32_t>(Media::MovingPhotoEffectMode::IMAGE_ONLY);
}

static int32_t InsertPhotoAsset()
{
    NativeRdb::ValuesBucket values;
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FDP->ConsumeBytesAsString(NUM_BYTES));
    const int32_t dirtyNumber = 100;
    values.PutInt(Media::PhotoColumn::PHOTO_DIRTY, FDP->ConsumeBool() ? 1 : dirtyNumber);
    values.PutLong(Media::MediaColumn::MEDIA_SIZE, FDP->ConsumeIntegral<int64_t>());
    int32_t thumbnailReady = 3;
    values.PutLong(Media::PhotoColumn::PHOTO_THUMBNAIL_READY, thumbnailReady);
    int32_t lcdVisitTime = 2;
    values.PutLong(Media::PhotoColumn::PHOTO_LCD_VISIT_TIME, lcdVisitTime);
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static Media::CheckedPhotoInfo FuzzCheckedPhotoInfo()
{
    Media::CheckedPhotoInfo checkedPhotoInfo = {
        .fileId = InsertPhotoAsset(),
        .path = "/storage/cloud/files/Photo/16",
        .subtype = FuzzPhotoSubType(),
        .movingPhotoEffectMode = FuzzMovingPhotoEffectMode()
    };
    return checkedPhotoInfo;
}

static vector<Media::CheckedPhotoInfo> FuzzVectorCheckedPhotoInfo()
{
    return {FuzzCheckedPhotoInfo()};
}

static void RepairNoOriginPhotoProcessorTest()
{
    InsertPhotoAsset();
    int32_t startFileId = 0;
    int32_t curFileId = -1;
    auto processor = Media::RepairNoOriginPhotoPrecessor();
    processor.QueryLcdPhotoCount(startFileId);
    processor.QueryPhotoInfo(startFileId);
    processor.HandlePhotoInfos(FuzzVectorCheckedPhotoInfo(), curFileId);
    processor.RepairNoOriginPhoto();
}

void SetTables()
{
    vector<string> createTableSqlList = { Media::PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null");
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::FDP = &fdp;
    if (data == nullptr || size < OHOS::MIN_SIZE) {
        return 0;
    }
    OHOS::RepairNoOriginPhotoProcessorTest();
    return 0;
}