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

#include "media_enhance_client.h"
#include "media_enhance_bundle.h"
#include "media_enhance_constants.h"
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
static inline uint32_t FuzzUInt32(const uint8_t *data, size_t size)
{
    return static_cast<uint32_t>(*data);
}

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

static inline vector<string> FuzzVectorIntToString(const uint8_t *data, size_t size)
{
    uint32_t value = FuzzUInt32(data, size);
    return {to_string(value)};
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

static inline Media::CloudEnhancementAvailableType FuzzCloudEnhancementAvailableType(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::CloudEnhancementAvailableType_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::CloudEnhancementAvailableType_FUZZER_LISTS[*data];
    }
    return Media::CloudEnhancementAvailableType::NOT_SUPPORT;
}
#endif

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
static void EnhancementManagerTest(const uint8_t *data, size_t size)
{
    Media::EnhancementManager::GetInstance().Init();
    vector<string> fileIds = FuzzVectorIntToString(data, size);
    vector<string> photoIds = FuzzVectorIntToString(data, size);
    Media::EnhancementManager::GetInstance().CancelTasksInternal(fileIds, photoIds,
        FuzzCloudEnhancementAvailableType(data, size));
    Media::EnhancementManager::GetInstance().RemoveTasksInternal(fileIds, photoIds);
    Media::EnhancementManager::GetInstance().RevertEditUpdateInternal(FuzzInt32(data, size));
    Media::EnhancementManager::GetInstance().RecoverTrashUpdateInternal(fileIds);

    DataSharePredicates predicates;
    string photoUri = "file://media/Photo/1/IMG_1722329102_000/" + TESTING_DISPLAYNAME;
    predicates.EqualTo(Media::MediaColumn::MEDIA_ID, photoUri);
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    cmd.SetDataSharePred(predicates);
    Media::EnhancementManager::GetInstance().HandleEnhancementUpdateOperation(cmd);
    vector<string> columns = FuzzVectorString(data, size);
    Media::EnhancementManager::GetInstance().HandleEnhancementQueryOperation(cmd, columns);

    MediaEnhance::MediaEnhanceBundle mediaEnhanceBundle;
    Media::EnhancementManager::GetInstance().AddServiceTask(mediaEnhanceBundle, FuzzInt32(data, size),
        FuzzString(data, size), FuzzBool(data, size));
}

static void EnhancementServiceAdpterTest(const uint8_t *data, size_t size)
{
    shared_ptr<Media::EnhancementServiceAdapter> enhancementService = make_shared<Media::EnhancementServiceAdapter>();
    enhancementService->LoadEnhancementService();

    MediaEnhance::MediaEnhanceBundle mediaEnhanceBundle;
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
    Media::EnhancementServiceCallback *callback = new Media::EnhancementServiceCallback();
    callback->OnServiceReconnected();

    MediaEnhance::MediaEnhanceBundle bundle;
    callback->OnSuccess(FuzzString(data, size), bundle);
    callback->OnFailed(FuzzString(data, size), bundle);

    const uint8_t* buffer = Media::BUFFER;
    shared_ptr<MediaEnhance::RawData> rawData = make_shared<MediaEnhance::RawData>(buffer, 0);
    shared_ptr<Media::CloudEnhancementFileInfo> fileInfo = make_shared<Media::CloudEnhancementFileInfo>(
        FuzzInt32(data, size), FuzzString(data, size), FuzzString(data, size), FuzzInt32(data, size), 0);
    callback->SaveCloudEnhancementPhoto(fileInfo, *rawData);
    callback->CreateCloudEnhancementPhoto(FuzzInt32(data, size), fileInfo);
}
#endif
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    OHOS::EnhancementManagerTest(data, size);
    OHOS::EnhancementServiceAdpterTest(data, size);
    OHOS::EnhancementServiceCallbackTest(data, size);
#endif
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    return 0;
}