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

#include "ptp_media_sync_observer.h"

#include <chrono>
#include <cctype>
#include <securec.h>

#include "media_log.h"
#include "ptp_album_handles.h"
#include "photo_album_column.h"
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "result_set_utils.h"
#include "media_file_uri.h"

using namespace std;

namespace OHOS {
namespace Media {
constexpr int32_t RESERVE_ALBUM = 10;
constexpr int32_t PARENT_ID = 0;
constexpr int32_t DELETE_LIMIT_TIME = 5000;
constexpr int32_t ERR_NUM = -1;
const string BURST_COVER_LEVEL = "1";
const string BURST_NOT_COVER_LEVEL = "2";
const string IS_LOCAL = "2";
const std::string HIDDEN_ALBUM = ".hiddenAlbum";
const string POSITION = "2";
const string INVALID_FILE_ID = "-1";
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
    MEDIA_DEBUG_LOG("MtpMediaLibrary album [%{public}d]", objectHandle);

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

static bool IsNumber(const string& str)
{
    CHECK_AND_RETURN_RET_LOG(!str.empty(), false, "IsNumber input is empty");
    for (char const& c : str) {
        if (isdigit(c) == 0) {
            return false;
        }
    }
    return true;
}

vector<int32_t> MediaSyncObserver::GetHandlesFromPhotosInfoBurstKeys(vector<std::string> &handles)
{
    vector<int32_t> handlesResult;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, handlesResult,
        "Mtp GetHandlesFromPhotosInfoBurstKeys fail to get datasharehelper");
    CHECK_AND_RETURN_RET_LOG(!handles.empty(), handlesResult, "Mtp handles have no elements!");
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    columns.push_back(PhotoColumn::PHOTO_BURST_KEY);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, BURST_COVER_LEVEL);
    predicates.IsNotNull(PhotoColumn::PHOTO_BURST_KEY);
    predicates.In(PhotoColumn::MEDIA_ID, handles);
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);

    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        handlesResult, "Mtp GetHandlesFromPhotosInfoBurstKeys fail to get PHOTO_BURST_KEY");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        handlesResult, "Mtp GetHandlesFromPhotosInfoBurstKeys have no PHOTO_BURST_KEY");
    vector<string> burstKey;
    do {
        burstKey.push_back(GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet));
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);

    CHECK_AND_RETURN_RET_LOG(!burstKey.empty(), handlesResult,
        "Mtp GetHandlesFromPhotosInfoBurstKeys burstKey is empty");

    columns.clear();
    columns.push_back(PhotoColumn::MEDIA_ID);
    DataShare::DataSharePredicates predicatesHandles;
    predicatesHandles.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, BURST_NOT_COVER_LEVEL);
    predicatesHandles.IsNotNull(PhotoColumn::PHOTO_BURST_KEY);
    predicatesHandles.In(PhotoColumn::PHOTO_BURST_KEY, burstKey);
    resultSet = dataShareHelper_->Query(uri, predicatesHandles, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        handlesResult, "Mtp GetHandlesFromPhotosInfoBurstKeys fail to get handles");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        handlesResult, "Mtp GetHandlesFromPhotosInfoBurstKeys have no handles");
    do {
        string file_id = GetStringVal(PhotoColumn::MEDIA_ID, resultSet);
        if (!IsNumber(file_id)) {
            MEDIA_ERR_LOG("Mtp GetHandlesFromPhotosInfoBurstKeys id is incorrect ");
            continue;
        }
        handlesResult.push_back(atoi(file_id.c_str()));
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    return handlesResult;
}

vector<string> MediaSyncObserver::GetAllDeleteHandles()
{
    vector<string> handlesResult;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, handlesResult,
        "Mtp GetAllDeleteHandles fail to get datasharehelper");
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    columns.push_back(MediaColumn::MEDIA_ID);
    DataShare::DataSharePredicates predicates;
    auto now = std::chrono::system_clock::now();
    auto now_milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    auto new_timestamp = now_milliseconds - DELETE_LIMIT_TIME;
    predicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(new_timestamp));
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);

    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        handlesResult, "Mtp GetAllDeleteHandles fail to get PHOTO_ALL_DELETE_KEY");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        handlesResult, "Mtp GetAllDeleteHandles have no PHOTO_ALL_DELETE_KEY");
    do {
        string file_id = GetStringVal(PhotoColumn::MEDIA_ID, resultSet);
        handlesResult.push_back(file_id);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    return handlesResult;
}

void MediaSyncObserver::AddPhotoHandle(int32_t handle)
{
    CHECK_AND_RETURN_LOG(dataShareHelper_ != nullptr, "Mtp AddPhotoHandle fail to get datasharehelper");
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    columns.push_back(PhotoColumn::PHOTO_OWNER_ALBUM_ID);
    columns.push_back(PhotoColumn::PHOTO_SUBTYPE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, to_string(handle));
    predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, POSITION);
    CHECK_AND_RETURN_LOG(dataShareHelper_ != nullptr, "Mtp AddPhotoHandle dataShareHelper_ is nullptr");
    resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Mtp AddPhotoHandle fail to get handles");
    CHECK_AND_RETURN_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        "Mtp AddPhotoHandle failed to get resultSet");
    SendEventPackets(handle + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_ADDED_CODE);
    int32_t ownerAlbumId = GetInt32Val(PhotoColumn::PHOTO_OWNER_ALBUM_ID, resultSet);
    int32_t subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        SendEventPackets(handle + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_ADDED_CODE);
        SendEventPacketAlbum(ownerAlbumId, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
    }
    auto albumHandles = PtpAlbumHandles::GetInstance();
    if (!albumHandles->FindHandle(ownerAlbumId)) {
        albumHandles->AddHandle(ownerAlbumId);
        SendEventPacketAlbum(ownerAlbumId, MTP_EVENT_OBJECT_ADDED_CODE);
        SendEventPacketAlbum(ownerAlbumId, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
        SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
    }
}

void MediaSyncObserver::GetAddEditPhotoHandles(int32_t handle)
{
    vector<int32_t> handlesResult;
    CHECK_AND_RETURN_LOG(dataShareHelper_ != nullptr,
        "Mtp GetAddEditPhotoHandles fail to get datasharehelper");
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    columns.push_back(PhotoColumn::PHOTO_SUBTYPE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, to_string(handle));
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Mtp GetAddEditPhotoHandles fail to get PHOTO_ALL_DELETE_KEY");
    CHECK_AND_RETURN_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        "Mtp GetAddEditPhotoHandles have no PHOTO_ALL_DELETE_KEY");

    do {
        int32_t subType = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
        if (subType == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            SendEventPackets(handle + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
        } else if (subType == static_cast<int32_t>(PhotoSubType::DEFAULT)) {
            SendEventPackets(handle + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
        }
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
}

int32_t MediaSyncObserver::GetAddEditAlbumHandle(int32_t handle)
{
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    columns.push_back(PhotoColumn::PHOTO_OWNER_ALBUM_ID);
    predicates.EqualTo(MediaColumn::MEDIA_ID, to_string(handle));
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        ERR_NUM, "Mtp GetAddEditAlbumHandle dataShareHelper_ is nullptr");
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        ERR_NUM, "Mtp GetAddEditAlbumHandle fail to get album id");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        ERR_NUM, "Mtp GetAddEditAlbumHandle have no row");
    int32_t album_id = GetInt32Val(PhotoColumn::PHOTO_OWNER_ALBUM_ID, resultSet);
    return album_id;
}

void MediaSyncObserver::SendPhotoRemoveEvent(std::string &suffixString)
{
    vector<string> allDeletedHandles;
    vector<int32_t> handles;
    if (suffixString.empty()) {
        allDeletedHandles = GetAllDeleteHandles();
        for (auto deleteHandle : allDeletedHandles) {
            if (!IsNumber(deleteHandle)) {
                MEDIA_ERR_LOG("Mtp SendPhotoRemoveEvent deleteHandle is incorrect ");
                continue;
            }
            SendEventPackets(atoi(deleteHandle.c_str()) + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
            SendEventPackets(atoi(deleteHandle.c_str()) + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
        }
    } else {
        CHECK_AND_RETURN_LOG(IsNumber(suffixString), "Mtp SendPhotoRemoveEvent deleteHandle is incorrect ");
        SendEventPackets(atoi(suffixString.c_str()) + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
        SendEventPackets(atoi(suffixString.c_str()) + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
        vector<std::string> allDeleted;
        allDeletedHandles.push_back(suffixString);
    }
    handles = GetHandlesFromPhotosInfoBurstKeys(allDeletedHandles);
    for (const auto handle : handles) {
        SendEventPackets(handle + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
    }
}

void MediaSyncObserver::SendPhotoEvent(ChangeType changeType, string suffixString)
{
    if (!suffixString.empty() && !std::isdigit(suffixString[0])) {
        return;
    }
    if (!suffixString.empty() && atoi(suffixString.c_str()) <= 0) {
        return;
    }
    switch (changeType) {
        case static_cast<int32_t>(NotifyType::NOTIFY_ADD):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO ADD");
            AddPhotoHandle(atoi(suffixString.c_str()));
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_UPDATE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO UPDATE");
            SendEventPackets(atoi(suffixString.c_str()) + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            GetAddEditPhotoHandles(atoi(suffixString.c_str()));
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_REMOVE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary PHOTO REMOVE");
            SendPhotoRemoveEvent(suffixString);
            break;
        default:
            break;
    }
}

std::shared_ptr<DataShare::DataShareResultSet> MediaSyncObserver::GetAlbumInfo()
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, nullptr,
        "MediaSyncObserver::GetAlbumInfo dataShareHelper_ is nullptr");
    DataShare::DataSharePredicates predicates;
    Uri uri(PAH_QUERY_PHOTO_ALBUM);
    vector<string> columns;
    columns.push_back(PhotoAlbumColumns::ALBUM_ID + " as " + MEDIA_DATA_DB_ID);
    predicates.IsNotNull(MEDIA_DATA_DB_ALBUM_NAME);
    predicates.NotEqualTo(MEDIA_DATA_DB_ALBUM_NAME, HIDDEN_ALBUM);
    predicates.BeginWrap();
    predicates.NotEqualTo(MEDIA_DATA_DB_IS_LOCAL, IS_LOCAL);
    predicates.Or();
    predicates.IsNull(MEDIA_DATA_DB_IS_LOCAL);
    predicates.EndWrap();
    return dataShareHelper_->Query(uri, predicates, columns);
}

void MediaSyncObserver::SendEventToPTP(int32_t suff_int, ChangeType changeType)
{
    auto albumHandles = PtpAlbumHandles::GetInstance();
    CHECK_AND_RETURN_LOG(albumHandles != nullptr, "albumHandles is nullptr");
    switch (changeType) {
        case static_cast<int32_t>(NotifyType::NOTIFY_ADD):
            MEDIA_DEBUG_LOG("MtpMediaLibrary ALBUM ADD");
            albumHandles->AddHandle(suff_int);
            SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_ADDED_CODE);
            SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_UPDATE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary ALBUM UPDATE");
            if (albumHandles->FindHandle(suff_int)) {
                SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            } else {
                albumHandles->AddHandle(suff_int);
                auto suff_removed_int = albumHandles->ChangeHandle(GetAlbumInfo());
                if (suff_removed_int != E_ERR) {
                    albumHandles->RemoveHandle(suff_removed_int);
                    SendEventPacketAlbum(suff_removed_int, MTP_EVENT_OBJECT_REMOVED_CODE);
                    SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                }
                SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_ADDED_CODE);
                SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
                SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            }
            break;
        case static_cast<int32_t>(NotifyType::NOTIFY_REMOVE):
            MEDIA_DEBUG_LOG("MtpMediaLibrary ALBUM REMOVE");
            albumHandles->RemoveHandle(suff_int);
            SendEventPacketAlbum(suff_int, MTP_EVENT_OBJECT_REMOVED_CODE);
            SendEventPacketAlbum(PARENT_ID, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            break;
        default:
            break;
    }
}

bool MediaSyncObserver::ParseNotifyData(const ChangeInfo &changeInfo, vector<string> &fileIds)
{
    if (changeInfo.data_ == nullptr || changeInfo.size_ <= 0) {
        MEDIA_DEBUG_LOG("changeInfo.data_ is null or changeInfo.size_ is invalid");
        return false;
    }
    MEDIA_DEBUG_LOG("changeInfo.size_ is %{public}d.", changeInfo.size_);
    uint8_t *parcelData = static_cast<uint8_t *>(malloc(changeInfo.size_));
    if (parcelData == nullptr) {
        MEDIA_ERR_LOG("parcelData malloc failed");
        return false;
    }
    if (memcpy_s(parcelData, changeInfo.size_, changeInfo.data_, changeInfo.size_) != 0) {
        MEDIA_ERR_LOG("parcelData copy parcel data failed");
        free(parcelData);
        return false;
    }
    shared_ptr<MessageParcel> parcel = make_shared<MessageParcel>();
    // parcel析构函数中会free掉parcelData，成功调用ParseFrom后不可进行free(parcelData)
    if (!parcel->ParseFrom(reinterpret_cast<uintptr_t>(parcelData), changeInfo.size_)) {
        MEDIA_ERR_LOG("Parse parcelData failed");
        free(parcelData);
        return false;
    }
    uint32_t len = 0;
    if (!parcel->ReadUint32(len)) {
        MEDIA_ERR_LOG("Failed to read sub uri list length");
        return false;
    }
    MEDIA_DEBUG_LOG("read sub uri list length: %{public}u .", len);
    for (uint32_t i = 0; i < len; i++) {
        string subUri = parcel->ReadString();
        if (subUri.empty()) {
            MEDIA_ERR_LOG("Failed to read sub uri");
            return false;
        }
        MEDIA_DEBUG_LOG("notify data subUri string %{public}s.", subUri.c_str());
        MediaFileUri fileUri(subUri);
        string fileId = fileUri.GetFileId();
        if (!IsNumber(fileId)) {
            MEDIA_ERR_LOG("Failed to read sub uri fileId");
            continue;
        }
        fileIds.push_back(fileId);
    }
    return true;
}

void MediaSyncObserver::HandleMovePhotoEvent(const ChangeInfo &changeInfo)
{
    if (changeInfo.changeType_ != static_cast<int32_t>(NotifyType::NOTIFY_ADD)) {
        return;
    }
    vector<string> fileIds;
    bool errCode = ParseNotifyData(changeInfo, fileIds);
    if (!errCode || fileIds.empty()) {
        MEDIA_DEBUG_LOG("parse changInfo data failed or have no fileId");
        return;
    }
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    columns.push_back(MediaColumn::MEDIA_ID);
    columns.push_back(PhotoColumn::PHOTO_SUBTYPE);
    predicates.In(MediaColumn::MEDIA_ID, fileIds);
    predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, POSITION);
    CHECK_AND_RETURN_LOG(dataShareHelper_ != nullptr, "Mtp dataShareHelper_ is nullptr");
    resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Mtp get handles failed");
    CHECK_AND_RETURN_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK, "Mtp get resultSet failed");
    do {
        int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        int32_t subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
        SendEventPackets(fileId + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
        SendEventPackets(fileId + COMMON_PHOTOS_OFFSET, MTP_EVENT_OBJECT_ADDED_CODE);
        if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            SendEventPackets(fileId + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_REMOVED_CODE);
            SendEventPackets(fileId + COMMON_MOVING_OFFSET, MTP_EVENT_OBJECT_ADDED_CODE);
        }
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
}

void MediaSyncObserver::OnChangeEx(const ChangeInfo &changeInfo)
{
    std::string PhotoPrefix = PhotoColumn::PHOTO_URI_PREFIX;
    std::string PhotoAlbumPrefix = PhotoAlbumColumns::ALBUM_URI_PREFIX;
    MEDIA_DEBUG_LOG("MtpMediaLibrary changeType [%{public}d]", changeInfo.changeType_);
    for (const auto& it : changeInfo.uris_) {
        std::string uri = it.ToString();
        MediaFileUri fileUri(uri);
        MEDIA_DEBUG_LOG("MtpMediaLibrary uris [%{public}s]", uri.c_str());
        if (startsWith(uri, PhotoPrefix)) {
            std::string fileId = fileUri.GetFileId();
            if (fileId.compare(INVALID_FILE_ID) == 0) {
                fileId = "";
            }
            if (fileId.empty() && changeInfo.changeType_ != static_cast<int32_t>(NotifyType::NOTIFY_REMOVE)) {
                MEDIA_DEBUG_LOG("MtpMediaLibrary suffixString is empty");
                continue;
            }
            MEDIA_DEBUG_LOG("MtpMediaLibrary suffixString [%{public}s]", fileId.c_str());
            SendPhotoEvent(changeInfo.changeType_, fileId);
        } else if (startsWith(uri, PhotoAlbumPrefix)) {
            std::string albumId = fileUri.GetFileId();
            MEDIA_DEBUG_LOG("MtpMediaLibrary suffixString [%{public}s]", albumId.c_str());
            if (!IsNumber(albumId)) {
                continue;
            }
            int32_t albumIdNum = atoi(albumId.c_str());
            if (albumIdNum <= RESERVE_ALBUM) {
                continue;
            }
            HandleMovePhotoEvent(changeInfo);
            SendEventToPTP(albumIdNum, changeInfo.changeType_);
        }
    }
}

void MediaSyncObserver::OnChange(const ChangeInfo &changeInfo)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ChangeInfo changeInfoCopy = changeInfo;
        if (changeInfo.data_ != nullptr && changeInfo.size_ > 0) {
            changeInfoCopy.data_ = malloc(changeInfo.size_);
            if (memcpy_s(const_cast<void*>(changeInfoCopy.data_),
                changeInfo.size_, changeInfo.data_, changeInfo.size_) != 0) {
                MEDIA_ERR_LOG("changeInfoCopy copy data failed");
                free(const_cast<void*>(changeInfoCopy.data_));
                return;
            }
        }
        changeInfoQueue_.push(changeInfoCopy);
    }
    cv_.notify_one();
}

void MediaSyncObserver::StartNotifyThread()
{
    MEDIA_INFO_LOG("start notify thread");
    CHECK_AND_PRINT_LOG(!isRunning_.load(), "MediaSyncObserver notify thread is already running");
    isRunning_.store(true);
    notifythread_ = std::thread([this] {this->ChangeNotifyThread();});
}

void MediaSyncObserver::StopNotifyThread()
{
    MEDIA_INFO_LOG("stop notify thread");
    isRunning_.store(false);
    cv_.notify_all();
    if (notifythread_.joinable()) {
        notifythread_.join();
    }
}

void MediaSyncObserver::ChangeNotifyThread()
{
    while (isRunning_.load()) {
        ChangeInfo changeInfo;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !changeInfoQueue_.empty() || !isRunning_.load(); });
            if (!isRunning_.load()) {
                MEDIA_INFO_LOG("notify thread is stopped");
                break;
            }
            changeInfo = changeInfoQueue_.front();
            changeInfoQueue_.pop();
        }
        OnChangeEx(changeInfo);
        if (changeInfo.data_ != nullptr) {
            free(const_cast<void*>(changeInfo.data_));
        }
    }
}
} // namespace Media
} // namespace OHOS