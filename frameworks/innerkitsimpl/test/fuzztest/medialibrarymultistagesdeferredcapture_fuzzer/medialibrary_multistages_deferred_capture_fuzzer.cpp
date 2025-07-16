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

#include "medialibrary_multistages_deferred_capture_fuzzer.h"

#include <cstdint>
#include <string>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include "ability_context_impl.h"
#include "media_log.h"
#include "rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "deferred_photo_proc_session.h"
#include "deferred_photo_proc_adapter.h"
#include "multistages_capture_deferred_photo_proc_session_callback.h"
#include "medialibrary_kvstore_manager.h"

namespace OHOS {
using namespace std;
static const int32_t E_ERR = -1;
static const int32_t NUM_BYTES = 1;
static const int32_t MAX_DPS_ERROR_CODE = 10;
static const string PHOTOS_TABLE = "Photos";
FuzzedDataProvider *provider = nullptr;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

static inline CameraStandard::DpsErrorCode FuzzDpsErrorCode()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_DPS_ERROR_CODE);
    return static_cast<CameraStandard::DpsErrorCode>(value);
}

static int32_t InsertAsset(string photoId)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::PhotoColumn::PHOTO_ID, photoId);
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, provider->ConsumeBytesAsString(NUM_BYTES));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

void SetTables()
{
    vector<string> createTableSqlList = { Media::PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null.");
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed.", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success.", createTableSql.c_str());
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
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibrary Mgr failed, ret: %{public}d.", ret);
    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr.");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

static void MultistagesCaptureDeferredPhotoProcAdapterTest()
{
    std::shared_ptr<Media::DeferredPhotoProcessingAdapter> deferredProcSession =
        make_shared<Media::DeferredPhotoProcessingAdapter>();
    deferredProcSession->BeginSynchronize();
    deferredProcSession->EndSynchronize();
    std::string photoId = provider->ConsumeBytesAsString(NUM_BYTES);
    std::string appName = provider->ConsumeBytesAsString(NUM_BYTES);
    deferredProcSession->RestoreImage(photoId);
    deferredProcSession->ProcessImage(appName, photoId);
    deferredProcSession->CancelProcessImage(photoId);
}

static void MultistagesCaptureDeferredPhotoProcSessionCallbackTest()
{
    Media::MultiStagesCaptureDeferredPhotoProcSessionCallback *callback =
        new Media::MultiStagesCaptureDeferredPhotoProcSessionCallback();
    std::string photoId = provider->ConsumeBytesAsString(NUM_BYTES);
    int32_t fileId = InsertAsset(photoId);
    MEDIA_DEBUG_LOG("fileId: %{public}d.", fileId);
    CameraStandard::DpsErrorCode errCode = FuzzDpsErrorCode();
    callback->OnError(photoId, errCode);
}

static inline void ClearKvStore()
{
    Media::MediaLibraryKvStoreManager::GetInstance()::CloseAllKvStore();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    OHOS::MultistagesCaptureDeferredPhotoProcAdapterTest();
    OHOS::MultistagesCaptureDeferredPhotoProcSessionCallbackTest();
    OHOS::ClearKvStore();
    return 0;
}