/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "NotificationClassification"

#include "notification_classification.h"

#include "media_log.h"
#include "medialibrary_common_utils.h"

using namespace std;
using namespace OHOS::Media::AccurateRefresh;
namespace OHOS {
namespace Media {
namespace Notification {
std::unordered_map<std::variant<AssetRefreshOperation, AlbumRefreshOperation>,
    std::function<std::vector<MediaChangeInfo>(NotifyInfoInner &)>>
    NotificationClassification::classificationMap = {
        {AssetRefreshOperation::ASSET_OPERATION_ADD, HandleAssetAdd},
        {AssetRefreshOperation::ASSET_OPERATION_ADD_HIDDEN, HandleAssetAddHidden},
        {AssetRefreshOperation::ASSET_OPERATION_ADD_TRASH, HandleAssetAddTrash},
        {AssetRefreshOperation::ASSET_OPERATION_REMOVE, HandleAssetRemove},
        {AssetRefreshOperation::ASSET_OPERATION_REMOVE_HIDDEN, HandleAssetRemoveHidden},
        {AssetRefreshOperation::ASSET_OPERATION_REMOVE_TRASH, HandleAssetRemoveTrash},

        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_NORMAL, HandleAssetUpdateNormal},
        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_REMOVE_NORMAL, HandleAssetUpdateRemoveNormal},
        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_ADD_NORMAL, HandleAssetUpdateAddNormal},
        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_HIDDEN, HandleAssetUpdateHidden},
        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_ADD_HIDDEN, HandleAssetUpdateAddHidden},
        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_REMOVE_HIDDEN, HandleAssetUpdateRemoveHidden},

        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_TRASH, HandleAssetUpdateTrash},
        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_ADD_TRASH, HandleAssetUpdateAddTrash},
        {AssetRefreshOperation::ASSET_OPERATION_UPDATE_REMOVE_TRASH, HandleAssetUpdateRemoveTrash},
        {AssetRefreshOperation::ASSET_OPERATION_TRASH, HandleAssetTrash},
        {AssetRefreshOperation::ASSET_OPERATION_UNTRASH, HandleAssetUntrash},
        {AssetRefreshOperation::ASSET_OPERATION_HIDDEN, HandleAssetHidden},
        {AssetRefreshOperation::ASSET_OPERATION_UNHIDDEN, HandleAssetUnhidden},
        {AssetRefreshOperation::ASSET_OPERATION_RECHECK, HandleAssetRecheck},

        {AlbumRefreshOperation::ALBUM_OPERATION_ADD, HandleAlbumAdd},
        {AlbumRefreshOperation::ALBUM_OPERATION_UPDATE, HandleAlbumUpdate},
        {AlbumRefreshOperation::ALBUM_OPERATION_REMOVE, HandleAlbumRemove},
        {AlbumRefreshOperation::ALBUM_OPERATION_UPDATE_HIDDEN, HandleAlbumUpdateHidden},
        {AlbumRefreshOperation::ALBUM_OPERATION_UPDATE_TRASH, HandleAlbumUpdateTrash},
        {AlbumRefreshOperation::ALBUM_OPERATION_RECHECK, HandleAlbumRecheck},
};
std::unordered_set<int32_t> NotificationClassification::addAlbumIdSet_;
std::mutex NotificationClassification::addAlbumIdMutex_;

NotificationClassification::NotificationClassification()
{}

NotificationClassification::~NotificationClassification()
{}

void NotificationClassification::ConvertNotification(
    std::vector<NotifyInfoInner> &notifyInfos, std::vector<MediaChangeInfo> &mediaChangeInfos)
{
    MEDIA_INFO_LOG("ConvertNotification");
    for (NotifyInfoInner notifyInfoInner : notifyInfos) {
        auto it = classificationMap.find(notifyInfoInner.operationType);
        if (it != classificationMap.end()) {
            std::vector<MediaChangeInfo> infos = it->second(notifyInfoInner);
            mediaChangeInfos.insert(mediaChangeInfos.end(), infos.begin(), infos.end());
        }
    }
}

MediaChangeInfo NotificationClassification::BuildMediaChangeInfo(
    NotifyInfoInner &notifyInfoInner, bool isForRecheck, NotifyType notifyType, NotifyUriType notifyUri)
{
    MediaChangeInfo mediaChangeInfo;
    std::vector<std::variant<PhotoAssetChangeData, AlbumChangeData>> changeInfos = notifyInfoInner.infos;
    mediaChangeInfo.changeInfos = changeInfos;
    mediaChangeInfo.isForRecheck = isForRecheck;
    mediaChangeInfo.notifyUri = notifyUri;
    mediaChangeInfo.notifyType = notifyType;
    return mediaChangeInfo;
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetAdd(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetAdd");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetAddHidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetAddHidden");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::HIDDEN_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetAddTrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetAddTrash");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateNormal(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateNormal");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_UPDATE, NotifyUriType::PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateRemoveNormal(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateRemoveNormal");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateAddNormal(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateAddNormal");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateHidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateHidden");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_UPDATE, NotifyUriType::HIDDEN_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateRemoveHidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateRemoveHidden");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::HIDDEN_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateAddHidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateAddHidden");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::HIDDEN_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateTrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateTrash");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_UPDATE, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateRemoveTrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateRemoveTrash");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUpdateAddTrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUpdateAddTrash");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetTrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetTrash");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::PHOTO_URI),
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUntrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUntrash");
    std::vector<NotifyDetailInfo> notifyDetails;
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::PHOTO_URI),
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetRemove(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetRemove");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetRemoveHidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetRemoveHidden");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::HIDDEN_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetRemoveTrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetRemoveTrash");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetHidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetHidden");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::PHOTO_URI),
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::HIDDEN_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAssetUnhidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetUnhidden");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::PHOTO_URI),
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ASSET_REMOVE, NotifyUriType::HIDDEN_PHOTO_URI)};
}
std::vector<MediaChangeInfo> NotificationClassification::HandleAssetRecheck(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAssetRecheck");
    return {BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::PHOTO_URI),
        BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::HIDDEN_PHOTO_URI),
        BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::TRASH_PHOTO_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAlbumAdd(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAlbumAdd");
    return {BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ALBUM_ADD, NotifyUriType::PHOTO_ALBUM_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAlbumRemove(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAlbumRemove");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ALBUM_REMOVE, NotifyUriType::PHOTO_ALBUM_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAlbumUpdate(NotifyInfoInner &notifyInfoInner)
{
    std::lock_guard<std::mutex> lock(addAlbumIdMutex_);
    MEDIA_INFO_LOG("HandleAlbumUpdate");
    if (!addAlbumIdSet_.empty()) {
        return HandleAlbumAddAndUpdate(notifyInfoInner);
    }
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ALBUM_UPDATE, NotifyUriType::PHOTO_ALBUM_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAlbumUpdateHidden(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAlbumHidden");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ALBUM_UPDATE, NotifyUriType::HIDDEN_ALBUM_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAlbumUpdateTrash(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAlbumTrash");
    return {
        BuildMediaChangeInfo(notifyInfoInner, false, NotifyType::NOTIFY_ALBUM_UPDATE, NotifyUriType::TRASH_ALBUM_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAlbumRecheck(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAlbumRecheck");
    return {BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ALBUM_ADD, NotifyUriType::PHOTO_ALBUM_URI),
        BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ALBUM_ADD, NotifyUriType::HIDDEN_ALBUM_URI),
        BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ALBUM_ADD, NotifyUriType::TRASH_ALBUM_URI)};
}

std::vector<MediaChangeInfo> NotificationClassification::HandleAlbumAddAndUpdate(NotifyInfoInner &notifyInfoInner)
{
    MEDIA_INFO_LOG("HandleAlbumAddAndUpdate");
    std::vector<MediaChangeInfo> mediaChangeInfo;
    MediaChangeInfo addMediaChangeInfo;
    MediaChangeInfo updateMediaChangeInfo;

    for (auto &info : notifyInfoInner.infos) {
        if (auto infoPtr = std::get_if<AccurateRefresh::AlbumChangeData>(&info)) {
            if (addAlbumIdSet_.find(infoPtr->infoBeforeChange_.albumId_) != addAlbumIdSet_.end()) {
                addAlbumIdSet_.erase(infoPtr->infoBeforeChange_.albumId_);
                infoPtr->infoBeforeChange_.albumId_ = AccurateRefresh::INVALID_INT32_VALUE;
                addMediaChangeInfo.changeInfos.emplace_back(info);
                continue;
            }
            updateMediaChangeInfo.changeInfos.emplace_back(info);
        }
    }

    addMediaChangeInfo.isForRecheck = false;
    addMediaChangeInfo.notifyUri = NotifyUriType::PHOTO_ALBUM_URI;
    addMediaChangeInfo.notifyType = NotifyType::NOTIFY_ALBUM_ADD;
    mediaChangeInfo.emplace_back(addMediaChangeInfo);

    updateMediaChangeInfo.isForRecheck = false;
    updateMediaChangeInfo.notifyUri = NotifyUriType::PHOTO_ALBUM_URI;
    updateMediaChangeInfo.notifyType = NotifyType::NOTIFY_ALBUM_UPDATE;
    mediaChangeInfo.emplace_back(updateMediaChangeInfo);

    return mediaChangeInfo;
}

void NotificationClassification::AddAlbum(const std::string &albumId)
{
    std::lock_guard<std::mutex> lock(addAlbumIdMutex_);
    MEDIA_INFO_LOG("addAlbumIdSet_ insert albumId: %{public}s", albumId.c_str());
    if (!MediaLibraryCommonUtils::CanConvertStrToInt32(albumId)) {
        MEDIA_ERR_LOG("can not convert albumId to int");
        return;
    }
    addAlbumIdSet_.emplace(std::stoi(albumId));
}
}  // namespace Notification
}  // namespace Media
}  // namespace OHOS