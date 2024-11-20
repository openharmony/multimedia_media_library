/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_log.h"
#include "ptp_media_sync_observer.h"
#include "photo_album_column.h"

using namespace std;

namespace OHOS {
namespace Media {
constexpr int32_t RESERVE_ALBUM = 10;
constexpr int32_t PARENT_ID = 0;

bool startsWith(const std::string& str, const std::string& prefix)
{
    if (prefix.size() > str.size() || prefix.empty() || str.empty()) {
        MEDIA_ERR_LOG("MtpMediaLibrary::StartsWith prefix size error");
        return false;
    }

    for (size_t i = 0; i < prefix.size(); ++i) {
        if (str[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

void MediaSyncObserver::SendEventPackets(uint32_t objectHandle, uint16_t eventCode)
{
    EventMtp event;
    event.length = MTP_CONTAINER_HEADER_SIZE + sizeof(objectHandle);
    vector<uint8_t> outBuffer;
    MtpPacketTool::PutUInt32(outBuffer, event.length);
    MtpPacketTool::PutUInt16(outBuffer, EVENT_CONTAINER_TYPE);
    MtpPacketTool::PutUInt16(outBuffer, eventCode);
    MtpPacketTool::PutUInt32(outBuffer, context_->transactionID);
    MtpPacketTool::PutUInt32(outBuffer, objectHandle);

    event.data = outBuffer;
    context_->mtpDriver->WriteEvent(event);
}

void MediaSyncObserver::SendEventPacketAlbum(uint32_t objectHandle, uint16_t eventCode)
{
    EventMtp event;
    event.length = MTP_CONTAINER_HEADER_SIZE + sizeof(objectHandle);
    vector<uint8_t> outBuffer;
    MtpPacketTool::PutUInt32(outBuffer, event.length);
    MtpPacketTool::PutUInt16(outBuffer, EVENT_CONTAINER_TYPE);
    MtpPacketTool::PutUInt16(outBuffer, eventCode);
    MtpPacketTool::PutUInt32(outBuffer, PARENT_ID);
    MtpPacketTool::PutUInt32(outBuffer, objectHandle);

    event.data = outBuffer;
    MEDIA_DEBUG_LOG("MtpMediaLibrary album [%{public}d]", objectHandle);
    context_->mtpDriver->WriteEvent(event);
}

void MediaSyncObserver::SendPhotoEvent(ChangeType changeType, string suffixString)
{
    switch (changeType) {
        case static_cast<int32_t>(NotifyType::NOTIFY_ADD):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO ADD");
            SendEventPackets(stoi(suffixString)+PHOTES_FILE_ID, MTP_EVENT_OBJECT_ADDED_CODE);
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_UPDATE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO UPDATE");
            SendEventPackets(stoi(suffixString)+PHOTES_FILE_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_REMOVE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO REMOVE");
            SendEventPackets(stoi(suffixString)+PHOTES_FILE_ID, MTP_EVENT_OBJECT_REMOVED_CODE);
            break;
        default:
            break;
    }
}

void MediaSyncObserver::OnChange(const ChangeInfo &changeInfo)
{
    std::string PhotoPrefix = PhotoColumn::PHOTO_URI_PREFIX;
    std::string PhotoAlbumPrefix = PhotoAlbumColumns::ALBUM_URI_PREFIX;
    MEDIA_DEBUG_LOG("MtpMediaLibrary changeType [%{public}d]", changeInfo.changeType_);
    for (const auto& it : changeInfo.uris_) {
        std::string uri = it.ToString();
        MEDIA_DEBUG_LOG("MtpMediaLibrary uris [%{public}s]", uri.c_str());
        if (startsWith(uri, PhotoPrefix)) {
            std::string suffixString = uri.substr(PhotoPrefix.size());
            if (suffixString.empty()) {
                continue;
            }
            SendPhotoEvent(changeInfo.changeType_, suffixString);
        } else if (startsWith(uri, PhotoAlbumPrefix)) {
            std::string suffixString = uri.substr(PhotoAlbumPrefix.size());
            MEDIA_ERR_LOG("MtpMediaLibrary suffixString [%{public}s]", suffixString.c_str());
            if (suffixString.empty()) {
                continue;
            }
            int32_t suff_int = stoi(suffixString);
            if (suff_int <= RESERVE_ALBUM) {
                continue;
            }
            switch (changeInfo.changeType_) {
                case static_cast<int32_t>(NotifyType::NOTIFY_ADD):
                    MEDIA_DEBUG_LOG("MtpMediaLibrary ALBUM ADD");
                    SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_ADDED_CODE);
                    SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                    SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                    break;
                case static_cast<int32_t>(NotifyType::NOTIFY_UPDATE):
                    MEDIA_DEBUG_LOG("MtpMediaLibrary ALBUM UPDATE");
                    SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                    SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                    break;
                case static_cast<int32_t>(NotifyType::NOTIFY_REMOVE):
                    MEDIA_DEBUG_LOG("MtpMediaLibrary ALBUM REMOVE");
                    SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_REMOVED_CODE);
                    SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                    break;
                default:
                    break;
            }
        }
    }
}
} // namespace Media
} // namespace OHOS
