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

#include "medialibrarynotification_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <pixel_map.h>
#include "media_observer_manager.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "medialibrary_restore.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_notify_new.h"
#include "notification_classification.h"
#include "notify_info_inner.h"
#include "media_change_info.h"
#include "notification_merging.h"
#include "notification_distribution.h"
#include "notify_info.h"
#include "media_datashare_stub_impl.h"
#include "data_ability_observer_interface.h"
#include "observer_info.h"
#include "data_ability_observer_stub.h"
#include "media_log.h"
#include "get_self_permissions.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <random>

namespace OHOS {
using namespace Media;
using namespace std;
const uint32_t NOTIFY_URI_TYPE_MAX = 7;
const uint32_t NOTIFY_TYPE_MAX = 5;
const uint32_t NOTIFY_TABLE_TYPE_MAX = 2;
const uint32_t ALBUM_REFRESH_OPERATION_MAX = 6;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;

const Media::AccurateRefresh::PhotoAssetChangeData changePhotoData = []() {
    Media::AccurateRefresh::PhotoAssetChangeData photoData;
    Media::AccurateRefresh::PhotoAssetChangeInfo assetChangeInfo;
    assetChangeInfo.fileId_ = 10;
    photoData.infoBeforeChange_ = assetChangeInfo;
    return photoData;
}();

const Media::AccurateRefresh::AlbumChangeData albumChangeData = []() {
    Media::AccurateRefresh::AlbumChangeData albumData;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo;
    albumInfo.albumId_ = 7;
    albumInfo.albumName_ = "相机相册";
    albumInfo.albumUri_ = "//storge//cloud//100//1";
    albumData.infoBeforeChange_ = albumInfo;
    return albumData;
}();

FuzzedDataProvider *provider = nullptr;

static inline Notification::NotifyType FuzzNotifyType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, NOTIFY_TYPE_MAX);
    return static_cast<Notification::NotifyType>(value);
}

static inline Notification::NotifyUriType FuzzNotifyUriType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, NOTIFY_URI_TYPE_MAX);
    return static_cast<Notification::NotifyUriType>(value);
}

static inline Notification::NotifyTableType FuzzNotifyTableType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, NOTIFY_TABLE_TYPE_MAX);
    return static_cast<Notification::NotifyTableType>(value);
}

static inline Notification::AlbumRefreshOperation FuzzAlbumRefreshOperation()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, ALBUM_REFRESH_OPERATION_MAX);
    return static_cast<Notification::AlbumRefreshOperation>(value);
}

std::pair<Media::Notification::NotifyUriType, Media::Notification::NotifyUriType> getTwoDifferentRandoms()
{
    int32_t firstUriType = provider->ConsumeIntegralInRange<int32_t>(0, NOTIFY_URI_TYPE_MAX);
    int32_t secondUriType = provider->ConsumeIntegralInRange<int32_t>(0, NOTIFY_URI_TYPE_MAX);
    return {
        static_cast<Media::Notification::NotifyUriType>(firstUriType),
        static_cast<Media::Notification::NotifyUriType>(secondUriType)
    };
}

static void Init()
{
    MEDIA_INFO_LOG("start init");
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    sptr<OHOS::AAFwk::IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    Notification::NotifyUriType PHOTO_URI = Notification::NotifyUriType::PHOTO_URI;
    Notification::NotifyUriType HIDDEN_PHOTO_URI = Notification::NotifyUriType::HIDDEN_PHOTO_URI;
    Notification::NotifyUriType TRASH_PHOTO_URI = Notification::NotifyUriType::TRASH_PHOTO_URI;
    Notification::NotifyUriType PHOTO_ALBUM_URI = Notification::NotifyUriType::PHOTO_ALBUM_URI;
    Notification::NotifyUriType HIDDEN_ALBUM_URI = Notification::NotifyUriType::HIDDEN_ALBUM_URI;
    Notification::NotifyUriType TRASH_ALBUM_URI = Notification::NotifyUriType::TRASH_ALBUM_URI;
    Notification::NotifyUriType ANALYSIS_ALBUM_URI = Notification::NotifyUriType::ANALYSIS_ALBUM_URI;
    Notification::NotifyUriType INVALID = Notification::NotifyUriType::INVALID;
    sptr<OHOS::AAFwk::IDataAbilityObserver> consumeEnumDataObserver = new (std::nothrow) IDataAbilityObserverTest();
    Notification::NotifyUriType consumeEnum = FuzzNotifyUriType();
    observerManager->AddObserver(PHOTO_URI, dataObserver);
    observerManager->AddObserver(HIDDEN_PHOTO_URI, dataObserver);
    observerManager->AddObserver(TRASH_PHOTO_URI, dataObserver);
    observerManager->AddObserver(PHOTO_ALBUM_URI, dataObserver);
    observerManager->AddObserver(HIDDEN_ALBUM_URI, dataObserver);
    observerManager->AddObserver(TRASH_ALBUM_URI, dataObserver);
    observerManager->AddObserver(ANALYSIS_ALBUM_URI, dataObserver);
    observerManager->AddObserver(INVALID, dataObserver);
    observerManager->AddObserver(consumeEnum, consumeEnumDataObserver);
    MEDIA_INFO_LOG("end init");
}

static void SetNotifyInfoInners(std::vector<Notification::NotifyInfoInner> &notifyInfoInners)
{
    MEDIA_INFO_LOG("start SetNotifyInfoInners");
    Notification::NotifyInfoInner firstNotifyInfoInner;
    firstNotifyInfoInner.tableType = FuzzNotifyTableType();
    int32_t instIndex = provider->ConsumeIntegralInRange<int32_t>(0, ASSET_REFRESH_OPERATION.size()-1);
    firstNotifyInfoInner.operationType = ASSET_REFRESH_OPERATION[instIndex];
    notifyInfoInners.push_back(firstNotifyInfoInner);
    Notification::MediaLibraryNotifyNew::NotifyInner(firstNotifyInfoInner);
    Notification::NotifyInfoInner secondNotifyInfoInner;
    secondNotifyInfoInner.tableType = FuzzNotifyTableType();
    secondNotifyInfoInner.operationType = FuzzAlbumRefreshOperation();
    notifyInfoInners.push_back(secondNotifyInfoInner);
    Notification::MediaLibraryNotifyNew::UpdateItem(secondNotifyInfoInner);
    Notification::MediaLibraryNotifyNew::DeleteItem(firstNotifyInfoInner);
    MEDIA_INFO_LOG("end SetNotifyInfoInners");
}

static void SetMediaChangeInfos(std::vector<Notification::MediaChangeInfo> &mediaChangeInfos)
{
    MEDIA_INFO_LOG("start SetMediaChangeInfos");
    Notification::MediaChangeInfo firstMediaChangeInfo;
    firstMediaChangeInfo.isForRecheck = provider->ConsumeBool();
    firstMediaChangeInfo.notifyUri = FuzzNotifyUriType();
    firstMediaChangeInfo.notifyType = FuzzNotifyType();
    firstMediaChangeInfo.isSystem = provider->ConsumeBool();
    firstMediaChangeInfo.changeInfos = {changePhotoData};
    mediaChangeInfos.push_back(firstMediaChangeInfo);

    Notification::MediaChangeInfo secondMediaChangeInfo;
    secondMediaChangeInfo.isForRecheck = provider->ConsumeBool();
    secondMediaChangeInfo.notifyUri = FuzzNotifyUriType();
    secondMediaChangeInfo.notifyType = FuzzNotifyType();
    secondMediaChangeInfo.isSystem = provider->ConsumeBool();
    secondMediaChangeInfo.changeInfos = {changePhotoData};
    mediaChangeInfos.push_back(secondMediaChangeInfo);

    Notification::MediaChangeInfo thirdMediaChangeInfo;
    thirdMediaChangeInfo.isForRecheck = provider->ConsumeBool();
    thirdMediaChangeInfo.notifyUri = FuzzNotifyUriType();
    thirdMediaChangeInfo.notifyType = FuzzNotifyType();
    thirdMediaChangeInfo.isSystem = provider->ConsumeBool();
    thirdMediaChangeInfo.changeInfos = {albumChangeData};
    mediaChangeInfos.push_back(thirdMediaChangeInfo);
    MEDIA_INFO_LOG("end SetMediaChangeInfos");
}

static void SetNotifyInfos(std::vector<Notification::NotifyInfo>& notifyInfos)
{
    MEDIA_INFO_LOG("start SetNotifyInfos");
    Notification::NotifyInfo firstNotifyInfo;
    auto [firstNotifyUriType, secondNotifyUriType] = getTwoDifferentRandoms();
    auto firstObserverManager = Notification::MediaObserverManager::GetObserverManager();
    sptr<OHOS::AAFwk::IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    firstObserverManager->AddObserver(firstNotifyUriType, dataObserver);
    std::vector<Notification::ObserverInfo> firstObserverInfos = firstObserverManager->FindObserver(firstNotifyUriType);
    firstNotifyInfo.observerInfos.insert(
        firstNotifyInfo.observerInfos.end(),
        firstObserverInfos.begin(), firstObserverInfos.end());
    std::vector<Notification::MediaChangeInfo> firstMediaChangeInfos;
    SetMediaChangeInfos(firstMediaChangeInfos);
    firstNotifyInfo.changeInfosMap[firstNotifyUriType] = firstMediaChangeInfos;
 
    Notification::NotifyInfo secondtNotifyInfo;
    auto secondObserverManager = Notification::MediaObserverManager::GetObserverManager();
    sptr<OHOS::AAFwk::IDataAbilityObserver> secondDataObserver = new (std::nothrow) IDataAbilityObserverTest();
    secondObserverManager->AddObserver(secondNotifyUriType, secondDataObserver);
    std::vector<Notification::ObserverInfo> secondObserverInfos =
        secondObserverManager->FindObserver(secondNotifyUriType);
    secondtNotifyInfo.observerInfos.insert(
        secondtNotifyInfo.observerInfos.end(),
        secondObserverInfos.begin(), secondObserverInfos.end());
    std::vector<Notification::MediaChangeInfo> secondMediaChangeInfos;
    SetMediaChangeInfos(secondMediaChangeInfos);
    secondtNotifyInfo.changeInfosMap[secondNotifyUriType] = secondMediaChangeInfos;
    notifyInfos.push_back(firstNotifyInfo);
    notifyInfos.push_back(secondtNotifyInfo);
    MEDIA_INFO_LOG("end SetNotifyInfos");
}

static void ConvertNotificationFuzzerTest()
{
    MEDIA_INFO_LOG("start ConvertNotificationFuzzerTest");
    std::vector<Notification::NotifyInfoInner> notifyInfoInners;
    SetNotifyInfoInners(notifyInfoInners);
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    SetMediaChangeInfos(mediaChangeInfos);
    Notification::NotificationClassification::ConvertNotification(notifyInfoInners, mediaChangeInfos);
    MEDIA_INFO_LOG("end ConvertNotificationFuzzerTest");
}

static void MergeNotifyInfoFuzzerTest()
{
    MEDIA_INFO_LOG("start MergeNotifyInfoFuzzerTest");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    SetMediaChangeInfos(mediaChangeInfos);
    Notification::NotificationMerging::MergeNotifyInfo(mediaChangeInfos);
    MEDIA_INFO_LOG("end MergeNotifyInfoFuzzerTest");
}

static void DistributeNotifyInfoFuzzerTest()
{
    MEDIA_INFO_LOG("start DistributeNotifyInfoFuzzerTest");
    std::vector<Notification::NotifyInfo> notifyInfos;
    SetNotifyInfos(notifyInfos);
    Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    MEDIA_INFO_LOG("end DistributeNotifyInfoFuzzerTest");
}

static void NotificationRegisterManagerFuzzerTest()
{
    MEDIA_INFO_LOG("start NotificationRegisterManagerFuzzerTest");
    Notification::NotifyUriType uri = FuzzNotifyUriType();
    Notification::NotifyUriType secondUri = FuzzNotifyUriType();
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    sptr<OHOS::AAFwk::IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    sptr<OHOS::AAFwk::IDataAbilityObserver> secondDataObserver = new (std::nothrow) IDataAbilityObserverTest();
    observerManager->AddObserver(uri, dataObserver);
    observerManager->AddObserver(secondUri, secondDataObserver);
    observerManager->FindObserver(uri);
    observerManager->FindObserver(secondUri);
    observerManager->GetObservers();
    observerManager->RemoveObserver(dataObserver->AsObject());
    observerManager->RemoveObserverWithUri(secondUri, secondDataObserver);
    observerManager->RemoveObserver(secondDataObserver->AsObject());
    observerManager->RemoveObserverWithUri(uri, dataObserver);
    MEDIA_INFO_LOG("start NotificationRegisterManagerFuzzerTest");
}

static void SetHapPermission()
{
    MEDIA_INFO_LOG("enter SetHapPermission");
    OHOS::Security::AccessToken::HapInfoParams info = {
        .userID = 100, // 100 UserID
        .bundleName = "com.ohos.test.screencapturetdd",
        .instIndex = 0, // 0 index
        .appIDDesc = "com.ohos.test.screencapturetdd",
        .isSystemApp = true
    };
 
    OHOS::Security::AccessToken::HapPolicyParams policy = {
        .apl = Security::AccessToken::APL_SYSTEM_BASIC,
        .domain = "test.domain.screencapturetdd",
        .permList = { },
        .permStateList = {
            {
                .permissionName = "ohos.permission.MANAGE_PRIVATE_PHOTOS",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.READ_IMAGEVIDEO",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.WRITE_IMAGEVIDEO",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            }
        }
    };
    OHOS::Security::AccessToken::AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = OHOS::Security::AccessToken::AccessTokenKit::AllocHapToken(info, policy);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_INFO_LOG("Set hap token failed, err: %{public}d", ret);
    }
}

static int32_t AddSeed()
{
    char *seedData = new char[OHOS::SEED_SIZE];
    for (int i = 0; i < OHOS::SEED_SIZE; i++) {
        seedData[i] = static_cast<char>(i % MAX_BYTE_VALUE);
    }

    const char* filename = "corpus/seed.txt";
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file) {
        MEDIA_ERR_LOG("Cannot open file filename:%{public}s", filename);
        delete[] seedData;
        return E_ERR;
    }
    file.write(seedData, OHOS::SEED_SIZE);
    file.close();
    delete[] seedData;
    MEDIA_INFO_LOG("seedData has been successfully written to file filename:%{public}s", filename);
    return E_OK;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::SetHapPermission();
    OHOS::AddSeed();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::provider = &provider;
    if (data == nullptr) {
        return 0;
    }
    OHOS::Init();
    OHOS::ConvertNotificationFuzzerTest();
    OHOS::MergeNotifyInfoFuzzerTest();
    OHOS::DistributeNotifyInfoFuzzerTest();
    OHOS::NotificationRegisterManagerFuzzerTest();
    return 0;
}