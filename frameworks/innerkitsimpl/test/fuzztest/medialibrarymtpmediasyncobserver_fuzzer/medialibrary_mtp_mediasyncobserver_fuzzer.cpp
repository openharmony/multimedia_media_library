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
#include "medialibrary_mtp_mediasyncobserver_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "close_session_data.h"
#include "media_log.h"
#include "media_library_custom_restore.h"
#include "userfile_manager_types.h"
#include "datashare_observer.h"
#include "datashare_helper.h"

#define private public
#include "ptp_media_sync_observer.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
static const int32_t NUM_BYTES = 1;
static const int32_t MAX_CHANGE_TYPE = 4;
constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;
FuzzedDataProvider *provider = nullptr;

static DataShareObserver::ChangeType FuzzChangeType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_CHANGE_TYPE);
    return static_cast<DataShareObserver::ChangeType>(value);
}

static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return nullptr;
    }
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(FUZZ_STORAGE_MANAGER_MANAGER_ID);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return nullptr;
    }
    sptr<IRemoteObject> token = remoteObj;
    return DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
}

static shared_ptr<MediaSyncObserver> InitMediaSyncObserver()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return nullptr;
    }
    shared_ptr<MediaSyncObserver> mediaSyncObserver = make_shared<MediaSyncObserver>();
    mediaSyncObserver->context_ = context;
    mediaSyncObserver->context_->mtpDriver = make_shared<MtpDriver>();
    mediaSyncObserver->dataShareHelper_ = CreateDataShareHelper();
    return mediaSyncObserver;
}

static void PtpMediaSyncObserverTest()
{
    shared_ptr<MediaSyncObserver> mediaSyncObserver = InitMediaSyncObserver();
    ChangeInfo changeInfo;
    string dataTest = provider->ConsumeBytesAsString(NUM_BYTES);
    changeInfo.data_ = dataTest.c_str();
    changeInfo.size_ = provider->ConsumeIntegral<uint32_t>();
    uint32_t objectHandle = provider->ConsumeIntegral<uint32_t>();
    uint16_t eventCode = provider->ConsumeIntegral<uint16_t>();
    int32_t handle = provider->ConsumeIntegral<int32_t>();
    DataShareObserver::ChangeType changeType = FuzzChangeType();
    string suffixString = "1";
    std::vector<std::string> handles;
    handles.push_back("handle");
    std::vector<int32_t> albumIds;
    albumIds.push_back(1);
    std::set<int32_t> albumIds_;
    mediaSyncObserver->OnChange(changeInfo);
    mediaSyncObserver->OnChangeEx(changeInfo);
    mediaSyncObserver->StartNotifyThread();
    mediaSyncObserver->StartDelayInfoThread();

    mediaSyncObserver->SendEventPackets(objectHandle, eventCode);
    mediaSyncObserver->SendEventPacketAlbum(objectHandle, eventCode);
    mediaSyncObserver->SendPhotoEvent(changeType, suffixString);
    mediaSyncObserver->GetHandlesFromPhotosInfoBurstKeys(handles);
    mediaSyncObserver->SendEventToPTP(changeType, albumIds);
    mediaSyncObserver->GetAllDeleteHandles();
    mediaSyncObserver->GetAlbumIdList(albumIds_);
    mediaSyncObserver->GetOwnerAlbumIdList(albumIds_);
    mediaSyncObserver->GetAddEditPhotoHandles(handle);
    mediaSyncObserver->GetAddEditAlbumHandle(handle);
    mediaSyncObserver->AddPhotoHandle(handle);
    mediaSyncObserver->SendPhotoRemoveEvent(suffixString);
    mediaSyncObserver->HandleMovePhotoEvent(changeInfo);

    mediaSyncObserver->StopDelayInfoThread();
    mediaSyncObserver->StopNotifyThread();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::InitMediaSyncObserver();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::PtpMediaSyncObserverTest();
    return 0;
}