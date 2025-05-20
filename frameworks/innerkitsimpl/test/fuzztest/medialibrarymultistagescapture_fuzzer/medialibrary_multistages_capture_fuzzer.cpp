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
#include "medialibrary_multistages_capture_fuzzer.h"

#include <cstdint>
#include <string>
#include <thread>
#include "ability_context_impl.h"
#include "media_log.h"
#include "rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "multistages_capture_manager.h"
#include "multistages_moving_photo_capture_manager.h"
#include "multistages_photo_capture_manager.h"
#include "multistages_video_capture_manager.h"

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

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    return Uri(FuzzString(data, size));
}

static inline Media::MediaLibraryCommand FuzzMediaLibraryCmd(const uint8_t *data, size_t size)
{
    return Media::MediaLibraryCommand(FuzzUri(data, size));
}

static int32_t InsertAsset(const uint8_t *data, size_t size, string photoId)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::PhotoColumn::PHOTO_ID, photoId);
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
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

static void MultistagesCaptureManagerTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "Failed to get rdb store.");
    std::string photoId = FuzzString(data, size);
    int32_t fileId = InsertAsset(data, size, photoId);
    MEDIA_DEBUG_LOG("fileId: %{public}d.", fileId);
    NativeRdb::RdbPredicates rdbPredicate(PHOTOS_TABLE);
    rdbPredicate.EqualTo(Media::MediaColumn::MEDIA_ID, fileId);
    rdbPredicate.EqualTo(Media::PhotoColumn::PHOTO_ID, photoId);
    Media::MultiStagesCaptureManager::RemovePhotos(rdbPredicate, true);
    Media::MultiStagesCaptureManager::RestorePhotos(rdbPredicate);
    Media::MultiStagesCaptureManager::QuerySubType(photoId);
    Media::MultiStagesCaptureManager::RemovePhotos(rdbPredicate, false);
}

static void MultistagesMovingPhotoCaptureManagerTest(const uint8_t *data, size_t size)
{
    std::string photoId = FuzzString(data, size);
    Media::MultiStagesMovingPhotoCaptureManager::SaveMovingPhotoVideoFinished(photoId);
    Media::MultiStagesMovingPhotoCaptureManager::AddVideoFromMovingPhoto(photoId);
}

static void MultistagesPhotoCaptureManagerTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    Media::MultiStagesPhotoCaptureManager &instance =
        Media::MultiStagesPhotoCaptureManager::GetInstance();
    instance.UpdateDbInfo(cmd);
    std::string photoId = FuzzString(data, size);
    instance.CancelProcessRequest(photoId);
    int32_t fileId = InsertAsset(data, size, photoId);
    MEDIA_DEBUG_LOG("fileId: %{public}d.", fileId);
    int32_t deferredProcType = FuzzInt32(data, size);
    instance.AddImage(fileId, photoId, deferredProcType);
    instance.IsPhotoDeleted(photoId);
}

static void MultistagesVideoCaptureManagerTest(const uint8_t *data, size_t size)
{
    std::string videoId = FuzzString(data, size);
    std::string filePath = FuzzString(data, size);
    Media::MultiStagesVideoCaptureManager &instance =
        Media::MultiStagesVideoCaptureManager::GetInstance();
    instance.AddVideoInternal(videoId, filePath);
    int32_t fileId = InsertAsset(data, size, videoId);
    instance.AddVideo(videoId, std::to_string(fileId), filePath);
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
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    OHOS::MultistagesCaptureManagerTest(data, size);
    OHOS::MultistagesMovingPhotoCaptureManagerTest(data, size);
    OHOS::MultistagesPhotoCaptureManagerTest(data, size);
    OHOS::MultistagesVideoCaptureManagerTest(data, size);
    return 0;
}