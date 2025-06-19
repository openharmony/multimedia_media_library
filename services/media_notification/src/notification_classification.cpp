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
NotificationClassification::NotificationClassification()
{}

NotificationClassification::~NotificationClassification()
{}

void NotificationClassification::ConvertNotification(
    std::vector<NotifyInfoInner> &notifyInfos, std::vector<MediaChangeInfo> &mediaChangeInfos)
{
    MEDIA_INFO_LOG("ConvertNotification");
    for (NotifyInfoInner notifyInfoInner : notifyInfos) {
        std::vector<MediaChangeInfo> infos = classificationMap[notifyInfoInner.operationType](notifyInfoInner);
        mediaChangeInfos.insert(mediaChangeInfos.end(), infos.begin(), infos.end());
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
    return {BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ASSET_ADD, NotifyUriType::PHOTO_URI)};
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
    MEDIA_INFO_LOG("HandleAlbumUpdate");
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
    return {BuildMediaChangeInfo(notifyInfoInner, true, NotifyType::NOTIFY_ALBUM_ADD, NotifyUriType::PHOTO_ALBUM_URI)};
}
}  // namespace Notification
}  // namespace Media
}  // namespace OHOS