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

#include "media_bgtask_aging_task_fuzzer.h"

#include <cstddef>
#include <sstream>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "media_file_utils.h"
#include "values_bucket.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "utime.h"

#define private public
#include "delete_temporary_photos_processor.h"
#undef private

using namespace OHOS::Media;
namespace OHOS {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static const int32_t E_ERR = -1;
static const int64_t ONE_HOURS_TO_SECONDS = 60 * 60 * 1000;
static const int32_t HOURS_48 = 48;
static const int32_t INSERT_300_DATA = 300;
static const int32_t NUM_BYTES = 1;
FuzzedDataProvider *FDP = nullptr;

int32_t InsertTempAsset(int32_t count, int64_t &outRowId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int32_t i = 0; i < count; i++) {
        NativeRdb::ValuesBucket value;
        value.Put(PhotoColumn::PHOTO_IS_TEMP, FDP->ConsumeBool());
        int64_t dataAdded = current - FDP->ConsumeIntegralInRange<int32_t>(0, HOURS_48) * ONE_HOURS_TO_SECONDS;
        value.Put(MediaColumn::MEDIA_DATE_ADDED, std::to_string(dataAdded));
        insertValues.push_back(value);
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::PHOTOS_TABLE, insertValues);
    return ret;
}

static void DeleteTemporaryPhotosProcessorFuzzTest()
{
    MEDIA_INFO_LOG("DeleteTemporaryPhotosProcessorFuzzTest start");
    int64_t outRow = -1;
    int32_t ret = InsertTempAsset(FDP->ConsumeIntegralInRange<int32_t>(0, INSERT_300_DATA), outRow);

    auto processor = DeleteTemporaryPhotosProcessor();
    if (FDP->ConsumeBool()) {
        processor.Stop("");
    }
    processor.DeleteTemporaryPhotos();
}

void SetTables()
{
    vector<string> createTableSqlList = {
        Media::PhotoColumn::CREATE_PHOTO_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
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
    if (data == nullptr) {
        return 0;
    }

    OHOS::DeleteTemporaryPhotosProcessorFuzzTest();
    return 0;
}
