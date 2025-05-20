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
#include "ability_context_impl.h"
#include "media_log.h"
#include "rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "deferred_photo_proc_session.h"
#include "deferred_photo_proc_adapter.h"
#include "multistages_capture_deferred_photo_proc_session_callback.h"

namespace OHOS {
using namespace std;
static const int32_t E_ERR = -1;
static const string PHOTOS_TABLE = "Photos";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    return static_cast<int32_t>(*data);
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline CameraStandard::DpsErrorCode FuzzDpsErrorCode(const uint8_t *data, size_t size)
{
    return static_cast<CameraStandard::DpsErrorCode>(FuzzInt32(data, size));
}

static int32_t InsertAsset(const uint8_t *data, size_t size, string photoId)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::PhotoColumn::PHOTO_ID, photoId);
    values.PurString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

void SetTables()
{
    vector<string> createTableSqlList = { Media::PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null");
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
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

static void MultistagesCaptureDeferredPhotoProcAdapterTest(const uint8_t *data, size_t size)
{
    std::shared_ptr<Media::DeferredPhotoProcessingAdapter> deferredProcSession =
        make_shared<Media::DeferredPhotoProcessingAdapter>();
    deferredProcSession->BeginSynchronize();
    deferredProcSession->EndSynchronize();
    std::string photoId = FuzzString(data, size);
    std::string appName = FuzzString(data, size);
    deferredProcSession->RestoreImage(photoId);
    deferredProcSession->ProcessImage(appName, photoId);
    deferredProcSession->CancelProcessImage(photoId);
}

static void MultistagesCaptureDeferredPhotoProcSessionCallbackTest(const uint8_t *data, size_t size)
{
    Media::MultiStagesCaptureDeferredPhotoProcSessionCallback *callback =
        new Media::MultiStagesCaptureDeferredPhotoProcSessionCallback();
    std::string photoId = FuzzString(data, size);
    int32_t fileId = InsertAsset(data, size, photoId);
    MEDIA_DEBUG_LOG("fileId: %{public}d.", fileId);
    CameraStandard::DpsErrorCode errCode = FuzzDpsErrorCode(data, size);
    callback->OnError(photoId, errCode);
}

} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char **argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(const uint8_t *data, size_t size)
{
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    MultistagesCaptureDeferredPhotoProcAdapterTest(data, size);
    MultistagesCaptureDeferredPhotoProcSessionCallbackTest(data, size);
    return 0;
}