/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <string>
#include "notification_test_data.h"
#include "photo_asset_change_info.h"
#include "album_change_info.h"
#include "media_change_info.h"
#include "notify_info.h"
#include "media_observer_manager.h"
#include "media_datashare_stub_impl.h"
#include "data_ability_observer_interface.h"
#include "observer_info.h"
#include "data_ability_observer_stub.h"
#include "media_log.h"
#include "notify_task_worker.h"
#include "get_self_permissions.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Media {
namespace Notification {
const Media::AccurateRefresh::PhotoAssetChangeData deletePhotoData1 = []() {
    Media::AccurateRefresh::PhotoAssetChangeData photoData;
    Media::AccurateRefresh::PhotoAssetChangeInfo assetChangeInfo;
    assetChangeInfo.fileId_ = 10;
    assetChangeInfo.uri_ = "file://media/Photo/1911/IMG_1739946997_1909/IMG_20250219_143457.jpg";
    assetChangeInfo.dateDay_ = "20250311";
    assetChangeInfo.ownerAlbumUri_ = "12";
    assetChangeInfo.isFavorite_ = true;
    assetChangeInfo.mediaType_ = 1;
    assetChangeInfo.isHidden_ = false;
    assetChangeInfo.dateTrashedMs_ = 2025041225;
    assetChangeInfo.strongAssociation_ = 1;
    assetChangeInfo.thumbnailVisible_ = 1;
    assetChangeInfo.dateAddedMs_ = 2025040102;
    assetChangeInfo.dateTakenMs_ = 2025010102;
    assetChangeInfo.subType_ = 1;
    assetChangeInfo.syncStatus_ = 1;
    assetChangeInfo.cleanFlag_ = 1;
    assetChangeInfo.timePending_ = 0;
    assetChangeInfo.isTemp_ = 0;
    assetChangeInfo.burstCoverLevel_ = 0;
    assetChangeInfo.ownerAlbumId_ = 12;
    assetChangeInfo.hiddenTime_ = 0;
    assetChangeInfo.displayName_ = "03bd2af39593e27c2057d75eea2df9a4.JPG";
    assetChangeInfo.path_ = "/storage/cloud/files/Photo/15/IMG_1742178740_2319.jpg";
    photoData.infoBeforeChange_ = assetChangeInfo;
    return photoData;
}();
const Media::AccurateRefresh::PhotoAssetChangeData deletePhotoData2 = []() {
    Media::AccurateRefresh::PhotoAssetChangeData photoData;
    Media::AccurateRefresh::PhotoAssetChangeInfo assetChangeInfo;
    assetChangeInfo.fileId_ = 11;
    assetChangeInfo.uri_ = "file://media/Photo/1911/IMG_1739946997_1909/IMG_20250525_hhh.jpg";
    assetChangeInfo.dateDay_ = "20250525";
    assetChangeInfo.ownerAlbumUri_ = "12";
    assetChangeInfo.isFavorite_ = true;
    assetChangeInfo.mediaType_ = 1;
    assetChangeInfo.isHidden_ = false;
    assetChangeInfo.dateTrashedMs_ = 2025042355;
    assetChangeInfo.strongAssociation_ = 1;
    assetChangeInfo.thumbnailVisible_ = 1;
    assetChangeInfo.dateAddedMs_ = 20251230102;
    assetChangeInfo.dateTakenMs_ = 20251230102;
    assetChangeInfo.subType_ = 1;
    assetChangeInfo.syncStatus_ = 1;
    assetChangeInfo.cleanFlag_ = 1;
    assetChangeInfo.timePending_ = 0;
    assetChangeInfo.isTemp_ = 0;
    assetChangeInfo.burstCoverLevel_ = 0;
    assetChangeInfo.ownerAlbumId_ = 12;
    assetChangeInfo.hiddenTime_ = 0;
    assetChangeInfo.displayName_ = "03bd2af39593e27c123202475eea2df9a4.JPG";
    assetChangeInfo.path_ = "/storage/cloud/files/Photo/15/IMG_1742178740_2319.jpg";
    photoData.infoBeforeChange_ = assetChangeInfo;
    return photoData;
}();

const Media::AccurateRefresh::AlbumChangeData albumChangeData1 = []() {
    Media::AccurateRefresh::AlbumChangeData albumData;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo;
    albumInfo.albumId_ = 7;
    albumInfo.lpath_ = "//storge//cloud//100//2";
    albumInfo.imageCount_ = 1;
    albumInfo.videoCount_ = 0;
    albumInfo.albumType_ = 1;
    albumInfo.albumSubType_ = 1;
    albumInfo.albumName_ = "相机相册";
    albumInfo.albumUri_ = "//storge//cloud//100//1";
    albumInfo.count_ = 1;
    albumInfo.coverUri_ = 1;
    albumInfo.hiddenCount_ = 0;
    albumInfo.hiddenCoverUri_ = "";
    albumInfo.isCoverChange_ = false;
    albumInfo.isHiddenCoverChange_ = false;
    albumData.infoBeforeChange_ = albumInfo;
    return albumData;
}();
const Media::AccurateRefresh::AlbumChangeData albumChangeData2 = []() {
    Media::AccurateRefresh::AlbumChangeData albumData;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo;
    albumInfo.albumId_ = 11;
    albumInfo.lpath_ = "//storge//cloud//100//2";
    albumInfo.imageCount_ = 1;
    albumInfo.videoCount_ = 0;
    albumInfo.albumType_ = 1;
    albumInfo.albumSubType_ = 1;
    albumInfo.albumName_ = "回收站相册";
    albumInfo.albumUri_ = "//storge//cloud//100//1";
    albumInfo.count_ = 1;
    albumInfo.coverUri_ = 1;
    albumInfo.hiddenCount_ = 0;
    albumInfo.hiddenCoverUri_ = "";
    albumInfo.isCoverChange_ = false;
    albumInfo.isHiddenCoverChange_ = false;
    albumData.infoBeforeChange_ = albumInfo;
    return albumData;
}();

const Media::AccurateRefresh::AlbumChangeData albumChangeData3 = []() {
    Media::AccurateRefresh::AlbumChangeData albumData;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo;
    albumInfo.albumId_ = 4;
    albumInfo.lpath_ = "//storge//cloud//100//2";
    albumInfo.imageCount_ = 1;
    albumInfo.videoCount_ = 0;
    albumInfo.albumType_ = 1;
    albumInfo.albumSubType_ = 1;
    albumInfo.albumName_ = "图片相册";
    albumInfo.albumUri_ = "//storge//cloud//100//1";
    albumInfo.count_ = 1;
    albumInfo.coverUri_ = 1;
    albumInfo.hiddenCount_ = 0;
    albumInfo.hiddenCoverUri_ = "";
    albumInfo.isCoverChange_ = false;
    albumInfo.isHiddenCoverChange_ = false;
    albumData.infoBeforeChange_ = albumInfo;
    return albumData;
}();

std::vector<Notification::MediaChangeInfo> NotificationTestData::getPhotoChangeInfos(
    const Notification::NotifyUriType &notifyUriType,
    const Notification::NotifyType &notifyType, bool isForRecheck)
{
    Media::Notification::MediaChangeInfo photoUriChangeInfo;
    const auto &deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto &deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    photoUriChangeInfo.changeInfos.push_back(deletePhotoData1);
    photoUriChangeInfo.changeInfos.push_back(deletePhotoData2);
    photoUriChangeInfo.isForRecheck = isForRecheck;
    photoUriChangeInfo.notifyUri = notifyUriType;
    photoUriChangeInfo.notifyType = notifyType;

    Media::Notification::MediaChangeInfo photoUriChangeInfo1;
    photoUriChangeInfo1.changeInfos.push_back(deletePhotoData1);
    photoUriChangeInfo1.changeInfos.push_back(deletePhotoData2);
    photoUriChangeInfo1.isForRecheck = isForRecheck;
    photoUriChangeInfo1.notifyUri = notifyUriType;
    photoUriChangeInfo1.notifyType = notifyType;
    return {photoUriChangeInfo, photoUriChangeInfo1};
}

std::vector<Notification::MediaChangeInfo> NotificationTestData::getPhotnChangeInfosByUriType(
    const Notification::NotifyUriType &notifyUriType, bool isForRecheck)
{
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    std::vector<Notification::MediaChangeInfo> photoUriAddChangeInfos =
        getPhotoChangeInfos(notifyUriType, NotifyType::NOTIFY_ASSET_ADD, isForRecheck);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoUriAddChangeInfos.begin(), photoUriAddChangeInfos.end());
    std::vector<Notification::MediaChangeInfo> photoUriUpdateChangeInfos =
        getPhotoChangeInfos(notifyUriType, NotifyType::NOTIFY_ASSET_UPDATE, isForRecheck);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoUriUpdateChangeInfos.begin(), photoUriUpdateChangeInfos.end());
    std::vector<Notification::MediaChangeInfo> photoUriRemoveChangeInfos =
        getPhotoChangeInfos(notifyUriType, NotifyType::NOTIFY_ASSET_REMOVE, isForRecheck);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoUriRemoveChangeInfos.begin(), photoUriRemoveChangeInfos.end());
    return mediaChangeInfos;
}

std::vector<Notification::MediaChangeInfo> NotificationTestData::getAlbumChangeInfos(
    const Notification::NotifyUriType &notifyUriType, const Notification::NotifyType &notifyType, bool isForRecheck)
{
    Media::Notification::MediaChangeInfo photoAlbumChangeInfo;
    const auto &albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto &albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    photoAlbumChangeInfo.isForRecheck = isForRecheck;
    photoAlbumChangeInfo.notifyUri = notifyUriType;
    photoAlbumChangeInfo.notifyType = notifyType;
    photoAlbumChangeInfo.changeInfos.push_back(albumChangeData1);
    photoAlbumChangeInfo.changeInfos.push_back(albumChangeData2);

    Media::Notification::MediaChangeInfo photoAlbumChangeInfo1;
    photoAlbumChangeInfo1.isForRecheck = isForRecheck;
    photoAlbumChangeInfo1.notifyUri = notifyUriType;
    photoAlbumChangeInfo1.notifyType = notifyType;
    photoAlbumChangeInfo1.changeInfos.push_back(albumChangeData1);
    photoAlbumChangeInfo1.changeInfos.push_back(albumChangeData2);
    return {photoAlbumChangeInfo, photoAlbumChangeInfo1};
}

std::vector<Notification::MediaChangeInfo> NotificationTestData::getAlbumChangeInfosByUriType(
    const Notification::NotifyUriType &notifyUriType, bool isForRecheck)
{
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    std::vector<Notification::MediaChangeInfo> photoUriAddChangeInfos =
        getAlbumChangeInfos(notifyUriType, NotifyType::NOTIFY_ASSET_ADD, isForRecheck);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoUriAddChangeInfos.begin(), photoUriAddChangeInfos.end());
    std::vector<Notification::MediaChangeInfo> photoUriUpdateChangeInfos =
        getAlbumChangeInfos(notifyUriType, NotifyType::NOTIFY_ASSET_UPDATE, isForRecheck);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoUriUpdateChangeInfos.begin(), photoUriUpdateChangeInfos.end());
    std::vector<Notification::MediaChangeInfo> photoUriRemoveChangeInfos =
        getAlbumChangeInfos(notifyUriType, NotifyType::NOTIFY_ASSET_REMOVE, isForRecheck);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoUriRemoveChangeInfos.begin(), photoUriRemoveChangeInfos.end());
    return mediaChangeInfos;
}

// 覆盖所NotifyUriType和NotifyType组合
std::vector<Notification::MediaChangeInfo> NotificationTestData::buildAssetsMediaChangeInfo()
{
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;

    // PHOTO_URI
    std::vector<Notification::MediaChangeInfo> photoUriInfos =
        getPhotnChangeInfosByUriType(NotifyUriType::PHOTO_URI, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoUriInfos.begin(), photoUriInfos.end());

    // HIDDEN_PHOTO_URI
    std::vector<Notification::MediaChangeInfo> hiddenPhotoUriInfos =
        getPhotnChangeInfosByUriType(NotifyUriType::HIDDEN_PHOTO_URI, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), hiddenPhotoUriInfos.begin(), hiddenPhotoUriInfos.end());

    // TRASH_PHOTO_URI
    std::vector<Notification::MediaChangeInfo> trashPhotoUriInfos =
        getPhotnChangeInfosByUriType(NotifyUriType::TRASH_PHOTO_URI, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), trashPhotoUriInfos.begin(), trashPhotoUriInfos.end());

    // PHOTO_ALBUM_URI
    std::vector<Notification::MediaChangeInfo> photoAlbumUriInfos =
        getAlbumChangeInfosByUriType(NotifyUriType::PHOTO_ALBUM_URI, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), photoAlbumUriInfos.begin(), photoAlbumUriInfos.end());

    // TRASH_ALBUM_URI
    std::vector<Notification::MediaChangeInfo> trashAlbumUriInfos =
        getAlbumChangeInfosByUriType(NotifyUriType::TRASH_ALBUM_URI, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), trashAlbumUriInfos.begin(), trashAlbumUriInfos.end());

    // HIDDEN_ALBUM_URI
    std::vector<Notification::MediaChangeInfo> hiddenAlbumUriInfos =
        getAlbumChangeInfosByUriType(NotifyUriType::HIDDEN_ALBUM_URI, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), hiddenAlbumUriInfos.begin(), hiddenAlbumUriInfos.end());

    // INVALID PHOTO
    std::vector<Notification::MediaChangeInfo> invalidPhotoUriInfos =
        getPhotnChangeInfosByUriType(NotifyUriType::INVALID, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), invalidPhotoUriInfos.begin(), invalidPhotoUriInfos.end());

    // INVALID ALBUM
    std::vector<Notification::MediaChangeInfo> invalidAlbumUriInfos =
        getAlbumChangeInfosByUriType(NotifyUriType::INVALID, false);
    mediaChangeInfos.insert(mediaChangeInfos.end(), invalidAlbumUriInfos.begin(), invalidAlbumUriInfos.end());

    return mediaChangeInfos;
}

Notification::NotifyInfo createBaseNotifyInfo(NotifyUriType uriType, bool isAlbum)
{
    Notification::NotifyInfo notifyInfo;
    std::vector<Notification::MediaChangeInfo> changeInfos = isAlbum ?
        NotificationTestData::getAlbumChangeInfosByUriType(uriType, isAlbum) :
        NotificationTestData::getPhotnChangeInfosByUriType(uriType, isAlbum);
    notifyInfo.changeInfosMap[uriType] = changeInfos;
    return notifyInfo;
}

void setupObserversByTestCase(
    const std::string& testName,
    std::unordered_map<NotifyUriType, std::vector<ObserverInfo>>& observerMap,
    Notification::NotifyInfo& photoUri,
    Notification::NotifyInfo& hiddenPhotoUri,
    Notification::NotifyInfo& trashPhotoUri,
    Notification::NotifyInfo& photoAlbumUri,
    Notification::NotifyInfo& hiddenAlbumUri,
    Notification::NotifyInfo& trashAlbumUri)
{
    static const std::unordered_map<std::string, std::vector<NotifyUriType>> testCaseMap = {
        {"test001", {NotifyUriType::PHOTO_URI}},
        {"test002", {NotifyUriType::HIDDEN_PHOTO_URI}},
        {"test003", {NotifyUriType::TRASH_PHOTO_URI}},
        {"test004", {NotifyUriType::PHOTO_ALBUM_URI}},
        {"test005", {NotifyUriType::HIDDEN_ALBUM_URI}},
        {"test006", {NotifyUriType::TRASH_ALBUM_URI}},
        {"test007", {NotifyUriType::HIDDEN_ALBUM_URI, NotifyUriType::TRASH_ALBUM_URI}},
        {"test008", {NotifyUriType::PHOTO_URI}},
        {"test009", {NotifyUriType::PHOTO_ALBUM_URI, NotifyUriType::TRASH_ALBUM_URI}},
        {"test010", {NotifyUriType::PHOTO_URI, NotifyUriType::HIDDEN_PHOTO_URI, NotifyUriType::TRASH_PHOTO_URI}},
        {"test011", {NotifyUriType::PHOTO_URI, NotifyUriType::HIDDEN_ALBUM_URI, NotifyUriType::TRASH_ALBUM_URI}},
        {"test012", {NotifyUriType::PHOTO_URI, NotifyUriType::TRASH_PHOTO_URI,
            NotifyUriType::PHOTO_ALBUM_URI, NotifyUriType::TRASH_ALBUM_URI}}
    };

    auto it = testCaseMap.find(testName);
    if (it == testCaseMap.end()) {
        return;
    }

    for (auto uriType : it->second) {
        switch (uriType) {
            case NotifyUriType::PHOTO_URI:
                photoUri.observerInfos = observerMap[uriType];
                if (testName == "test010") {
                    photoUri.changeInfosMap[uriType].at(0).changeInfos.clear();
                }
                break;
            case NotifyUriType::HIDDEN_PHOTO_URI:
                hiddenPhotoUri.observerInfos = observerMap[uriType]; break;
            case NotifyUriType::TRASH_PHOTO_URI:
                trashPhotoUri.observerInfos = observerMap[uriType];
                if (testName == "test008") {
                    trashPhotoUri.observerInfos = observerMap[NotifyUriType::PHOTO_URI];
                }
                break;
            case NotifyUriType::PHOTO_ALBUM_URI:
                photoAlbumUri.observerInfos = observerMap[uriType]; break;
            case NotifyUriType::HIDDEN_ALBUM_URI:
                hiddenAlbumUri.observerInfos = observerMap[uriType]; break;
            case NotifyUriType::TRASH_ALBUM_URI:
                trashAlbumUri.observerInfos = observerMap[uriType]; break;
            default:
                break;
        }
    }
}

std::vector<Notification::NotifyInfo> NotificationTestData::buildAssetsNotifyInfo(
    const std::string &testName,
    std::unordered_map<NotifyUriType, std::vector<ObserverInfo>> observerMap)
{
    std::vector<Notification::NotifyInfo> notifyInfos;
    Notification::NotifyInfo photoUri = createBaseNotifyInfo(NotifyUriType::PHOTO_URI, false);
    Notification::NotifyInfo hiddenPhotoUri = createBaseNotifyInfo(NotifyUriType::HIDDEN_PHOTO_URI, false);
    Notification::NotifyInfo trashPhotoUri = createBaseNotifyInfo(NotifyUriType::TRASH_PHOTO_URI, false);
    Notification::NotifyInfo photoAlbumUri = createBaseNotifyInfo(NotifyUriType::PHOTO_ALBUM_URI, true);
    Notification::NotifyInfo hiddenAlbumUri = createBaseNotifyInfo(NotifyUriType::HIDDEN_ALBUM_URI, false);
    Notification::NotifyInfo trashAlbumUri  = createBaseNotifyInfo(NotifyUriType::TRASH_ALBUM_URI, false);
    setupObserversByTestCase(testName, observerMap, photoUri, hiddenPhotoUri,
        trashPhotoUri, photoAlbumUri, hiddenAlbumUri, trashAlbumUri);
    notifyInfos.insert(notifyInfos.end(), {
        photoUri, hiddenPhotoUri, trashPhotoUri,
        photoAlbumUri, hiddenAlbumUri, trashAlbumUri
    });

    return notifyInfos;
}

std::vector<NotifyInfoInner> NotificationTestData::buildPhotoNotifyTaskInfo(Notification::NotifyTableType tableType,
    std::vector<AccurateRefresh::PhotoAssetChangeData> infos, Notification::AssetRefreshOperation operationType,
    Notification::NotifyLevel notifyLevel)
{
    std::vector<Notification::NotifyInfoInner> notifyInfoInners;
    Notification::NotifyInfoInner notifyInfoInner;

    notifyInfoInner.tableType = tableType;
    notifyInfoInner.infos.insert(notifyInfoInner.infos.end(), infos.begin(), infos.end());
    notifyInfoInner.operationType = operationType;
    notifyInfoInner.notifyLevel = notifyLevel;

    notifyInfoInners.push_back(notifyInfoInner);

    return notifyInfoInners;
}

std::vector<NotifyInfoInner> NotificationTestData::buildAlbumNotifyTaskInfo(Notification::NotifyTableType tableType,
    std::vector<AccurateRefresh::AlbumChangeData> infos, Notification::AlbumRefreshOperation operationType,
    Notification::NotifyLevel notifyLevel)
{
    std::vector<Notification::NotifyInfoInner> notifyInfoInners;
    Notification::NotifyInfoInner notifyInfoInner;

    notifyInfoInner.tableType = tableType;
    notifyInfoInner.infos.insert(notifyInfoInner.infos.end(), infos.begin(), infos.end());
    notifyInfoInner.operationType = operationType;
    notifyInfoInner.notifyLevel = notifyLevel;

    notifyInfoInners.push_back(notifyInfoInner);

    return notifyInfoInners;
}

void NotificationTestData::SetHapPermission()
{
    Security::AccessToken::HapInfoParams info = {
        .userID = 100, // 100 UserID
        .bundleName = "com.ohos.test.screencapturetdd",
        .instIndex = 0, // 0 index
        .appIDDesc = "com.ohos.test.screencapturetdd",
        .isSystemApp = true
    };

    Security::AccessToken::HapPolicyParams policy = {
        .apl = Security::AccessToken::APL_SYSTEM_BASIC,
        .domain = "test.domain.screencapturetdd",
        .permList = { },
        .permStateList = {
            {
                .permissionName = "ohos.permission.MANAGE_PRIVATE_PHOTOS",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.READ_IMAGEVIDEO",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            },
            {
                .permissionName = "ohos.permission.WRITE_IMAGEVIDEO",
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            }
        }
    };
    Security::AccessToken::AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(info, policy);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_INFO_LOG("Set hap token failed, err: %{public}d", ret);
    }
    MEDIA_INFO_LOG("end SetHapPermission");
}

}  // namespace Notification
}  // namespace Media
}  // namespace OHOS