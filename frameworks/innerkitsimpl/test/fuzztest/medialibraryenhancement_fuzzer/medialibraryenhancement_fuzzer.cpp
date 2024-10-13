/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibraryenhancement_fuzzer.h"

#include <cstdint>
#include <string>

#include "ability_context_impl.h"
#include "data_ability_observer_interface.h"
#include "datashare_business_error.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "medialibrary_command.h"
#include "media_datashare_ext_ability.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore.h"
#include "medialibrary_unistore_manager.h"
#include "media_file_ext_ability.h"

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#define private public
#define protected public
#include "file_utils.h"
#include "enhancement_manager.h"
#include "enhancement_service_callback.h"
#include "enhancement_task_manager.h"
#include "enhancement_service_adapter.h"
#include "enhancement_database_operations.h"
#undef private
#undef protected
#endif

#include "media_datashare_stub_impl.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "runtime.h"

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
using namespace DataShare;
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
static const string TESTING_DISPLAYNAME = "IMG_20240904_133901.jpg";
static const int32_t isEven = 2;
static const int32_t NO = 0;
static const int32_t YES = 1;
static const int32_t E_ERR = -1;
static const string PHOTOS_TABLE = "Photos";
static const string PHOTO_URI_PREFIX = "file://media/Photo/";
static const string PHOTO_URI_PREFIX_UNDEDINED = "undedined/";

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    return static_cast<int32_t>(*data);
}

static inline int32_t FuzzBool(const uint8_t *data, size_t size)
{
    if (size % isEven == 0) {
        return true;
    }
    return false;
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
}

static inline Uri FuzzUriWithKeyValue(const uint8_t *data, size_t size, string uriStr)
{
    if (FuzzBool(data, size)) {
        Media::MediaFileUtils::UriAppendKeyValue(uriStr, Media::MEDIA_OPERN_KEYWORD, "true");
    } else {
        Media::MediaFileUtils::UriAppendKeyValue(uriStr, Media::MEDIA_OPERN_KEYWORD, "false");
    }
    Uri addTask(uriStr);
    return addTask;
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::ENHANCEMENT_FUZZER_URI_LISTS.size());
    if (*data < length) {
        string uriStr = Media::ENHANCEMENT_FUZZER_URI_LISTS[*data];
        return FuzzUriWithKeyValue(data, size, uriStr);
    }
    return Uri("Undefined");
}

static inline Media::MediaLibraryCommand FuzzMediaLibraryCmd(const uint8_t *data, size_t size)
{
    return Media::MediaLibraryCommand(FuzzUri(data, size));
}

static inline Media::CloudEnhancementAvailableType FuzzCloudEnhancementAvailableType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CloudEnhancementAvailableType::NOT_SUPPORT) &&
        value <= static_cast<int32_t>(Media::CloudEnhancementAvailableType::TRASH)) {
        return static_cast<Media::CloudEnhancementAvailableType>(value);
    }
    return Media::CloudEnhancementAvailableType::PROCESSING;
}

static inline void FuzzMimeTypeAndDisplayNameExtension(const uint8_t *data, size_t size, string &mimeType,
    string &displayName)
{
    uint8_t length = static_cast<uint8_t>(Media::DISPLAY_NAME_EXTENSION_FUZZER_LISTS.size());
    if (*data < length) {
        mimeType = Media::MIMETYPE_FUZZER_LISTS[*data];
        displayName = FuzzString(data, size) + Media::DISPLAY_NAME_EXTENSION_FUZZER_LISTS[*data];
    }
}

static inline int32_t FuzzDynamicRangeType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::DynamicRangeType::SDR) &&
        value <= static_cast<int32_t>(Media::DynamicRangeType::HDR)) {
        return value;
    }
    return static_cast<int32_t>(Media::DynamicRangeType::SDR);
}

static inline int32_t FuzzPhotoSubType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::PhotoSubType::DEFAULT) &&
        value <= static_cast<int32_t>(Media::PhotoSubType::SUBTYPE_END)) {
        return value;
    }
    return static_cast<int32_t>(Media::PhotoSubType::CAMERA);
}

static inline int32_t FuzzCEErrorCodeType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CEErrorCodeType::LIMIT_USAGE) &&
        value <= static_cast<int32_t>(Media::CEErrorCodeType::TASK_CANNOT_EXECUTE)) {
        return value;
    }
    return static_cast<int32_t>(Media::CEErrorCodeType::NON_RECOVERABLE);
}

static int32_t InsertAsset(const uint8_t *data, size_t size, string photoId)
{
    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_ERR;
    }
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::PhotoColumn::PHOTO_ID, photoId);
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));

    string mimeType = "undefined";
    string displayName = ".undefined";
    FuzzMimeTypeAndDisplayNameExtension(data, size, mimeType, displayName);
    values.PutString(Media::MediaColumn::MEDIA_NAME, displayName);
    values.PutString(Media::MediaColumn::MEDIA_MIME_TYPE, mimeType);
    int32_t hidden = FuzzBool(data, size) ? YES : NO;
    values.PutInt(Media::MediaColumn::MEDIA_HIDDEN, hidden);
    values.PutInt(Media::PhotoColumn::PHOTO_SUBTYPE, FuzzPhotoSubType(data, size));
    values.PutInt(Media::PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, FuzzDynamicRangeType(data, size));
    int32_t hasCloudWatermark = FuzzBool(data, size) ? YES : NO;
    values.PutInt(Media::PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, hasCloudWatermark);
    values.PutInt(Media::PhotoColumn::PHOTO_CE_AVAILABLE,
        static_cast<int32_t>(FuzzCloudEnhancementAvailableType(data, size)));

    int64_t fileId = 0;
    rdbStorePtr->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static MediaEnhance::MediaEnhanceBundleHandle* FuzzMediaEnhanceBundle(const uint8_t* data, size_t size, string photoId)
{
    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    Media::EnhancementManager::GetInstance().enhancementService_->PutInt(mediaEnhanceBundle,
        MediaEnhance::MediaEnhance_Bundle_Key::ERROR_CODE, FuzzCEErrorCodeType(data, size));
    return mediaEnhanceBundle;
}
#endif

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
static void EnhancementManagerTest(const uint8_t *data, size_t size)
{
    int32_t fileId = InsertAsset(data, size, FuzzString(data, size));
    Media::EnhancementManager::GetInstance().Init();
    vector<string> fileIds = { to_string(fileId) };
    vector<string> photoIds;
    Media::EnhancementManager::GetInstance().CancelTasksInternal(fileIds, photoIds,
        FuzzCloudEnhancementAvailableType(data, size));
    Media::EnhancementManager::GetInstance().RemoveTasksInternal(fileIds, photoIds);
    Media::EnhancementManager::GetInstance().RevertEditUpdateInternal(FuzzInt32(data, size));
    Media::EnhancementManager::GetInstance().RecoverTrashUpdateInternal(fileIds);

    DataSharePredicates predicates;
    string prefix = FuzzBool(data, size) ? PHOTO_URI_PREFIX : PHOTO_URI_PREFIX_UNDEDINED;
    string photoUri = prefix + "1/IMG_1722329102_000/" + TESTING_DISPLAYNAME;
    predicates.EqualTo(Media::MediaColumn::MEDIA_ID, photoUri);
    int32_t hasCloudWatermark = FuzzBool(data, size) ? YES : NO;
    predicates.EqualTo(Media::PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, hasCloudWatermark);
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    cmd.SetDataSharePred(predicates);
    Media::EnhancementManager::GetInstance().HandleEnhancementUpdateOperation(cmd);
    vector<string> columns = FuzzVectorString(data, size);
    Media::EnhancementManager::GetInstance().HandleEnhancementQueryOperation(cmd, columns);

    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    Media::EnhancementManager::GetInstance().AddServiceTask(mediaEnhanceBundle, FuzzInt32(data, size),
        FuzzString(data, size), FuzzBool(data, size));
}

static void EnhancementTaskManagerTest(const uint8_t *data, size_t size)
{
    int32_t fileId = FuzzInt32(data, size);
    string photoId = FuzzString(data, size);
    Media::EnhancementTaskManager::AddEnhancementTask(fileId, photoId);
    Media::EnhancementTaskManager::RemoveEnhancementTask(photoId);
    Media::EnhancementTaskManager::RemoveEnhancementTask(photoId);

    vector<string> taskIds = FuzzVectorString(data, size);
    Media::EnhancementTaskManager::RemoveAllEnhancementTask(taskIds);

    fileId = FuzzInt32(data, size);
    photoId = FuzzString(data, size);
    Media::EnhancementTaskManager::AddEnhancementTask(fileId, photoId);
    Media::EnhancementTaskManager::InProcessingTask(photoId);
    Media::EnhancementTaskManager::QueryPhotoIdByFileId(fileId);

    photoId = FuzzString(data, size);
    Media::EnhancementTaskManager::SetTaskRequestCount(photoId, FuzzInt32(data, size));
    Media::EnhancementTaskManager::GetTaskRequestCount(photoId);
}

static void CloudEnhancementGetCountTest(const uint8_t *data, size_t size)
{
    Media::CloudEnhancementGetCount& cloudEnhancementGetCount = Media::CloudEnhancementGetCount::GetInstance();
    cloudEnhancementGetCount.GetStartTimes();
    string photoId = FuzzString(data, size);
    cloudEnhancementGetCount.AddStartTime(photoId);
    cloudEnhancementGetCount.Report(FuzzString(data, size), photoId);
    cloudEnhancementGetCount.RemoveStartTime(photoId);
    cloudEnhancementGetCount.RemoveStartTime(photoId);
}

static void EnhancementServiceAdpterTest(const uint8_t *data, size_t size)
{
    shared_ptr<Media::EnhancementServiceAdapter> enhancementService = make_shared<Media::EnhancementServiceAdapter>();
    enhancementService->LoadEnhancementService();

    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    string photoId = FuzzString(data, size);
    enhancementService->AddTask(FuzzString(data, size), mediaEnhanceBundle);
    enhancementService->RemoveTask(FuzzString(data, size));
    enhancementService->CancelTask(FuzzString(data, size));
    enhancementService->CancelAllTasks();

    vector<string> taskIdList = FuzzVectorString(data, size);
    enhancementService->GetPendingTasks(taskIdList);
}

static void EnhancementServiceCallbackTest(const uint8_t *data, size_t size)
{
    Media::EnhancementServiceCallback::OnServiceReconnected();

    string photoId = FuzzString(data, size);
    MediaEnhance::MediaEnhanceBundleHandle* bundle = FuzzMediaEnhanceBundle(data, size, photoId);
    Media::EnhancementServiceCallback::OnSuccess(photoId.c_str(), bundle);
    string photoId = FuzzString(data, size);
    MediaEnhance::MediaEnhanceBundleHandle* bundle = FuzzMediaEnhanceBundle(data, size, photoId);
    Media::EnhancementServiceCallback::OnFailed(photoId.c_str(), bundle);

    uint8_t* buffer = Media::BUFFER;
    string displayName = FuzzString(data, size) + ".jpg";
    int32_t hidden = FuzzBool(data, size) ? YES : NO;
    shared_ptr<Media::CloudEnhancementFileInfo> fileInfo = make_shared<Media::CloudEnhancementFileInfo>(
        FuzzInt32(data, size), FuzzString(data, size), displayName, FuzzPhotoSubType(data, size), hidden);
    Media::CloudEnhancementThreadTask task(FuzzString(data, size),
        FuzzInt32(data, size), buffer, FuzzUInt32(data, size), FuzzBool(data, size));
    Media::EnhancementServiceCallback::SaveCloudEnhancementPhoto(fileInfo, task);
    Media::EnhancementServiceCallback::CreateCloudEnhancementPhoto(FuzzInt32(data, size), fileInfo);
    Media::EnhancementServiceCallback::DealWithSuccessedTask(task);
    Media::EnhancementServiceCallback::DealWithFailedTask(task);
    Media::EnhancementServiceCallback::UpdateAlbumsForCloudEnhancement();
}
#endif
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    OHOS::EnhancementManagerTest(data, size);
    OHOS::EnhancementTaskManagerTest(data, size);
    OHOS::CloudEnhancementGetCountTest(data, size);
    OHOS::EnhancementServiceAdpterTest(data, size);
    OHOS::EnhancementServiceCallbackTest(data, size);
#endif
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    return 0;
}