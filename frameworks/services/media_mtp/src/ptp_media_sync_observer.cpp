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
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "result_set_utils.h"

using namespace std;

namespace OHOS {
namespace Media {
constexpr int32_t RESERVE_ALBUM = 10;
constexpr int32_t PARENT_ID = 0;
const string BURST_COVER_LEVEL = "1";
const string BURST_NOT_COVER_LEVEL = "2";
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
    CHECK_AND_RETURN_LOG(context_ != nullptr, "Mtp Ptp context is nullptr");
    MtpPacketTool::PutUInt32(outBuffer, context_->transactionID);
    MtpPacketTool::PutUInt32(outBuffer, objectHandle);

    event.data = outBuffer;
    CHECK_AND_RETURN_LOG(context_->mtpDriver != nullptr, "Mtp Ptp mtpDriver is nullptr");
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
    CHECK_AND_RETURN_LOG(context_ != nullptr, "Mtp Ptp context is nullptr");
    CHECK_AND_RETURN_LOG(context_->mtpDriver != nullptr, "Mtp Ptp mtpDriver is nullptr");
    context_->mtpDriver->WriteEvent(event);
}

vector<int32_t> MediaSyncObserver::GetHandlesFromPhotosInfoBurstKeys(int32_t handle)
{
    vector<int32_t> handlesResult;
    if (dataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("MtpMedialibraryManager::GetPhotosInfo fail to get datasharehelper");
        return handlesResult;
    }
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    columns.push_back(PhotoColumn::PHOTO_BURST_KEY);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, BURST_COVER_LEVEL);
    predicates.IsNotNull(PhotoColumn::PHOTO_BURST_KEY);
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(handle));
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);

    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        handlesResult, "MtpMedialibraryManager fail to get PHOTO_BURST_KEY");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        handlesResult, "MtpMedialibraryManager have no PHOTO_BURST_KEY");
    string burstKey = GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet);
    if (burstKey.empty()) {
        MEDIA_ERR_LOG("MtpMedialibraryManager::burstKey is empty");
        return handlesResult;
    }

    columns.clear();
    columns.push_back(PhotoColumn::MEDIA_ID);
    DataShare::DataSharePredicates predicatesHandles;
    predicatesHandles.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, BURST_NOT_COVER_LEVEL);
    predicatesHandles.IsNotNull(PhotoColumn::PHOTO_BURST_KEY);
    predicatesHandles.EqualTo(PhotoColumn::PHOTO_BURST_KEY, burstKey);
    resultSet = dataShareHelper_->Query(uri, predicatesHandles, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        handlesResult, "MtpMedialibraryManager fail to get handles");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        handlesResult, "MtpMedialibraryManager have no handles");
    do {
        string file_id = GetStringVal(PhotoColumn::MEDIA_ID, resultSet);
        handlesResult.push_back(stoi(file_id));
    } while (resultSet->GoToNextRow()==NativeRdb::E_OK);
    return handlesResult;
}

void MediaSyncObserver::SendPhotoEvent(ChangeType changeType, string suffixString)
{
    if (stoi(suffixString) <= 0) {
        return;
    }
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    vector<int32_t> handles;
    switch (changeType) {
        case static_cast<int32_t>(NotifyType::NOTIFY_ADD):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO ADD");
            SendEventPackets(stoi(suffixString) + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_ADDED_CODE);
            columns.push_back(MediaColumn::MEDIA_NAME);
            predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(stoi(suffixString)));
            predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)));
            CHECK_AND_RETURN_LOG(dataShareHelper_ != nullptr, "Mtp dataShareHelper_ is nullptr");
            resultSet = dataShareHelper_->Query(uri, predicates, columns);
            CHECK_AND_RETURN_LOG(resultSet != nullptr, "Mtp fail to get handles");
            if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
                SendEventPackets(stoi(suffixString) + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_ADDED_CODE);
            }
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_UPDATE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO UPDATE");
            SendEventPackets(stoi(suffixString) + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_REMOVE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO REMOVE");
            SendEventPackets(stoi(suffixString) + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
            SendEventPackets(stoi(suffixString) + EDITED_PHOTOS_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
            SendEventPackets(stoi(suffixString) + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
            SendEventPackets(stoi(suffixString) + EDITED_MOVING_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
            handles = GetHandlesFromPhotosInfoBurstKeys(stoi(suffixString));
            for (const auto handle: handles) {
                SendEventPackets(handle+COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
            }
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
                MEDIA_ERR_LOG("MtpMediaLibrary suffixString is empty");
                continue;
            }
            MEDIA_DEBUG_LOG("MtpMediaLibrary suffixString [%{public}s]", suffixString.c_str());
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