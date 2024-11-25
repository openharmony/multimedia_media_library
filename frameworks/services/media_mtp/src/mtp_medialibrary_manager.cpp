/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MtpMedialibraryManager"
#include "mtp_medialibrary_manager.h"

#include <unistd.h>
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "datashare_result_set.h"
#include "directory_ex.h"
#include "fetch_result.h"
#include "image_format_convert.h"
#include "image_packer.h"
#include "image_source.h"
#include "media_column.h"
#include "mtp_data_utils.h"
#include "media_file_utils.h"
#include "media_mtp_utils.h"
#include "mtp_error_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "media_smart_map_column.h"
#include "moving_photo_file_utils.h"
#include "photo_album_column.h"
#include "ptp_media_sync_observer.h"
#include "pixel_map.h"
#include "ptp_medialibrary_manager_uri.h"
#include "system_ability_definition.h"
#include "userfilemgr_uri.h"

using namespace std;

namespace OHOS {
namespace Media {
constexpr int32_t NORMAL_WIDTH = 256;
constexpr int32_t NORMAL_HEIGHT = 256;
constexpr int32_t COMPRE_SIZE_LEVEL_1 = 256;
constexpr int32_t COMPRE_SIZE_LEVEL_2 = 204800;
const string THUMBNAIL_FORMAT = "image/jpeg";
static constexpr uint8_t THUMBNAIL_MID = 90;
constexpr int32_t PARENT_ID = 0;
const string API_VERSION = "api_version";
const string POSITION = "2";
const string IS_LOCAL = "2";
const string ALBUM_MEDIA_TYPE = "7";
const int64_t DATE_UNTRASHED = 0;
const int32_t SPECIAL_PTHOTO_TYPE = 2;
const std::string PARENT = "parent";
const std::string HIDDEN_ALBUM = ".hiddenAlbum";
const string BURST_COVER_LEVEL = "1";

std::shared_ptr<MtpMedialibraryManager> MtpMedialibraryManager::instance_ = nullptr;
std::mutex MtpMedialibraryManager::mutex_;
shared_ptr<DataShare::DataShareHelper> MtpMedialibraryManager::dataShareHelper_ = nullptr;
std::shared_ptr<MediaSyncObserver> mediaPhotoObserver_ = nullptr;
std::shared_ptr<MediaSyncObserver> mediaPhotoAlbumObserver_ = nullptr;
MtpMedialibraryManager::MtpMedialibraryManager(void)
{
}

MtpMedialibraryManager::~MtpMedialibraryManager(void)
{
}

std::shared_ptr<MtpMedialibraryManager> MtpMedialibraryManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<MtpMedialibraryManager>();
        }
    }
    return instance_;
}

void MtpMedialibraryManager::Init(const sptr<IRemoteObject> &token)
{
    if (dataShareHelper_ == nullptr) {
        dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
    if (mediaPhotoObserver_ == nullptr) {
        mediaPhotoObserver_ = std::make_shared<MediaSyncObserver>();
    }
    if (mediaPhotoAlbumObserver_ == nullptr) {
        mediaPhotoAlbumObserver_ = std::make_shared<MediaSyncObserver>();
    }
    mediaPhotoObserver_->context_ = context_;
    mediaPhotoObserver_->dataShareHelper_ = dataShareHelper_;
    mediaPhotoAlbumObserver_->context_ = context_;
    mediaPhotoAlbumObserver_->dataShareHelper_ = dataShareHelper_;
    dataShareHelper_->RegisterObserverExt(Uri(PhotoColumn::PHOTO_URI_PREFIX), mediaPhotoObserver_, true);
    dataShareHelper_->RegisterObserverExt(Uri(PhotoAlbumColumns::ALBUM_URI_PREFIX), mediaPhotoAlbumObserver_, true);
}

void MtpMedialibraryManager::SetContext(const shared_ptr<MtpOperationContext> &context)
{
    context_ = context;
}

int32_t MtpMedialibraryManager::GetHandles(int32_t parentId, vector<int> &outHandles, MediaType mediaType)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    DataShare::DataSharePredicates predicates;
    vector<string> columns;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    if (parentId == PARENT_ID) {
        Uri uri(PAH_QUERY_PHOTO_ALBUM);
        columns.push_back(PhotoAlbumColumns::ALBUM_ID + " as " + MEDIA_DATA_DB_ID);
        columns.push_back(PhotoAlbumColumns::ALBUM_NAME + " as " + MEDIA_DATA_DB_NAME);
        columns.push_back(ALBUM_MEDIA_TYPE + " as " + MEDIA_DATA_DB_MEDIA_TYPE);
        columns.push_back(PhotoAlbumColumns::ALBUM_DATE_MODIFIED);
        predicates.IsNotNull(MEDIA_DATA_DB_ALBUM_NAME);
        predicates.NotEqualTo(MEDIA_DATA_DB_ALBUM_NAME, HIDDEN_ALBUM);
        predicates.NotEqualTo(MEDIA_DATA_DB_IS_LOCAL, IS_LOCAL);
        resultSet = dataShareHelper_->Query(uri, predicates, columns);
    } else {
        Uri uri(PAH_QUERY_PHOTO);
        columns.push_back(MediaColumn::MEDIA_ID + " + " + to_string(COMMON_PHOTOS_OFFSET) + " as " + MEDIA_DATA_DB_ID);
        columns.push_back(MediaColumn::MEDIA_SIZE);
        columns.push_back(MediaColumn::MEDIA_NAME);
        columns.push_back(PhotoColumn::PHOTO_OWNER_ALBUM_ID +" as " + PARENT);
        columns.push_back(MediaColumn::MEDIA_DATE_ADDED);
        columns.push_back(MediaColumn::MEDIA_DURATION);
        columns.push_back(MediaColumn::MEDIA_TYPE);
        columns.push_back(PhotoColumn::PHOTO_SUBTYPE);
        columns.push_back(PhotoColumn::PHOTO_EDIT_TIME);
        DataShare::DataSharePredicates predicates;
        predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(parentId));
        predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, POSITION);
        predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, "0");
        predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, "0");
        predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, "0");
        resultSet = dataShareHelper_->Query(uri, predicates, columns);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_NO_SUCH_FILE), "fail to get handles");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        MtpErrorUtils::SolveGetHandlesError(E_SUCCESS), "have no handles");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t id = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        outHandles.push_back(id);
    }
    resultSet->GoToFirstRow();
    return MtpErrorUtils::SolveGetHandlesError(E_SUCCESS);
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::GetAlbumInfo(
    const shared_ptr<MtpOperationContext> &context, bool isHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, nullptr, "context is nullptr");
    if (dataShareHelper_ == nullptr) {
        MEDIA_INFO_LOG("MtpMedialibraryManager::GetAlbumInfo fail to get datasharehelpe");
        return nullptr;
    }
    DataShare::DataSharePredicates predicates;
    Uri uri(PAH_QUERY_PHOTO_ALBUM);
    vector<string> columns;
    columns.push_back(PhotoAlbumColumns::ALBUM_ID + " as " + MEDIA_DATA_DB_ID);
    columns.push_back(PhotoAlbumColumns::ALBUM_NAME + " as " + MEDIA_DATA_DB_NAME);
    columns.push_back(ALBUM_MEDIA_TYPE + " as " + MEDIA_DATA_DB_MEDIA_TYPE);
    columns.push_back(PhotoAlbumColumns::ALBUM_DATE_MODIFIED);
    predicates.IsNotNull(MEDIA_DATA_DB_ALBUM_NAME);
    predicates.NotEqualTo(MEDIA_DATA_DB_ALBUM_NAME, HIDDEN_ALBUM);
    predicates.BeginWrap();
    predicates.NotEqualTo(MEDIA_DATA_DB_IS_LOCAL, IS_LOCAL);
    predicates.Or();
    predicates.IsNull(MEDIA_DATA_DB_IS_LOCAL);
    predicates.EndWrap();
    if (!isHandle) {
        predicates.EqualTo(MEDIA_DATA_DB_ALBUM_ID, to_string(context->handle));
    }
    return dataShareHelper_->Query(uri, predicates, columns);
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::GetPhotosInfo(
    const shared_ptr<MtpOperationContext> &context, bool isHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, nullptr, "context is nullptr");
    if (dataShareHelper_ == nullptr) {
        MEDIA_INFO_LOG("MtpMedialibraryManager::GetPhotosInfo fail to get datasharehelpe");
        return nullptr;
    }
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    columns.push_back(MediaColumn::MEDIA_ID + " + " + to_string(COMMON_PHOTOS_OFFSET) + " as " + MEDIA_DATA_DB_ID);
    columns.push_back(MediaColumn::MEDIA_SIZE);
    columns.push_back(MediaColumn::MEDIA_NAME);
    columns.push_back(PhotoColumn::PHOTO_OWNER_ALBUM_ID +" as " + PARENT);
    columns.push_back(MediaColumn::MEDIA_DATE_ADDED);
    columns.push_back(MediaColumn::MEDIA_DURATION);
    columns.push_back(MediaColumn::MEDIA_TYPE);
    columns.push_back(MediaColumn::MEDIA_FILE_PATH);
    columns.push_back(PhotoColumn::PHOTO_SUBTYPE);
    columns.push_back(PhotoColumn::PHOTO_EDIT_TIME);
    columns.push_back(PhotoColumn::MEDIA_DATE_MODIFIED);
    DataShare::DataSharePredicates predicates;
    if (isHandle) {
        vector<string> burstKeys = GetBurstKeyFromPhotosInfo();
        predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(context->parent));
        predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, POSITION);
        predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, "0");
        predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, "0");
        predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, "0");
        if (!burstKeys.empty()) {
            predicates.BeginWrap()
                ->NotIn(PhotoColumn::PHOTO_BURST_KEY, burstKeys)
                ->Or()
                ->IsNull(PhotoColumn::PHOTO_BURST_KEY)
                ->EndWrap();
        }
    } else {
        int32_t file_id = context->handle % COMMON_PHOTOS_OFFSET;
        predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(file_id));
    }
    return dataShareHelper_->Query(uri, predicates, columns);
}

vector<string> MtpMedialibraryManager::GetBurstKeyFromPhotosInfo()
{
    if (dataShareHelper_ == nullptr) {
        MEDIA_INFO_LOG("MtpMedialibraryManager::GetBurstKeyFromPhotosInfo fail to get datasharehelpe");
        return vector<string>();
    }
    vector<string> bustKeys;
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    columns.push_back(PhotoColumn::PHOTO_BURST_KEY);
    DataShare::DataSharePredicates predicates;
    predicates.NotEqualTo(PhotoColumn::MEDIA_DATE_TRASHED, "0");
    predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, BURST_COVER_LEVEL);
    predicates.IsNotNull(PhotoColumn::PHOTO_BURST_KEY);
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        vector<string>(), "fail to get handles");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        vector<string>(), "have no handles");
    do {
        string bustKey = GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet);
        bustKeys.push_back(bustKey);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    return bustKeys;
}

int32_t MtpMedialibraryManager::HaveMovingPhotesHandle(const shared_ptr<DataShare::DataShareResultSet> resultSet,
    shared_ptr<UInt32List> &outHandles, const uint32_t parent)
{
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return E_HAS_DB_ERROR;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t id = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        outHandles->push_back(id);
        int32_t subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
        int32_t editTime = GetInt32Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet);
        MEDIA_INFO_LOG("MtpMedialibraryManager::HaveMovingPhotesHandle subtype:%{public}d, editTime:%{public}d",
            subtype, editTime);
        if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            uint32_t videoId = id - COMMON_PHOTOS_OFFSET + COMMON_MOVING_OFFSET;
            outHandles->push_back(videoId);
        }
        if (editTime > 0) {
            uint32_t editPhotoId = id - COMMON_PHOTOS_OFFSET + EDITED_PHOTOS_OFFSET;
            outHandles->push_back(editPhotoId);
        }
        if (editTime > 0 && subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            uint32_t editVideoId = id - COMMON_PHOTOS_OFFSET + EDITED_MOVING_OFFSET;
            outHandles->push_back(editVideoId);
        }
    }
    return E_SUCCESS;
}

int32_t MtpMedialibraryManager::GetHandles(const shared_ptr<MtpOperationContext> &context,
    shared_ptr<UInt32List> &outHandles)
{
    string extension;
    MediaType mediaType;
    CHECK_AND_RETURN_RET_LOG(context != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "context is nullptr");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    int32_t errCode = MtpDataUtils::SolveHandlesFormatData(context->format, extension, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS,
        MtpErrorUtils::SolveGetHandlesError(errCode), "fail to SolveHandlesFormatData");
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->parent == PARENT_ID) {
        resultSet = GetAlbumInfo(context, true);
    } else {
        resultSet = GetPhotosInfo(context, true);
    }
    errCode = HaveMovingPhotesHandle(resultSet, outHandles, context->parent);
    return MtpErrorUtils::SolveGetHandlesError(errCode);
}

int32_t MtpMedialibraryManager::GetObjectInfo(const shared_ptr<MtpOperationContext> &context,
    shared_ptr<ObjectInfo> &outObjectInfo)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr,
        MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR), "context is nullptr");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    DataShare::DataSharePredicates predicates;
    MEDIA_INFO_LOG("GetObjectInfo %{public}d,%{public}d", context->handle, context ->parent);
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->parent == PARENT_ID && context->handle < COMMON_PHOTOS_OFFSET) {
        resultSet = GetAlbumInfo(context, false);
    } else {
        resultSet = GetPhotosInfo(context, false);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE), "fail to get object set");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE), "have no handles");
    return SetObject(resultSet, context, outObjectInfo);
}

uint32_t MtpMedialibraryManager::GetSizeFromOfft(const off_t &size)
{
    return size > std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max() : size;
}

int32_t MtpMedialibraryManager::SetObject(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
    const shared_ptr<MtpOperationContext> &context, std::shared_ptr<ObjectInfo> &outObjectInfo)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "resultSet is nullptr");
    do {
        if (static_cast<int32_t>(context->handle / COMMON_PHOTOS_OFFSET) < SPECIAL_PTHOTO_TYPE) {
            unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
            CHECK_AND_RETURN_RET_LOG(fetchFileResult != nullptr,
                MTP_ERROR_INVALID_OBJECTHANDLE, "fetchFileResult is nullptr");
            unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
            return SetObjectInfo(fileAsset, outObjectInfo);
        }
        string display_name = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
        string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
        int32_t subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
        string sourcePath = MtpDataUtils::GetMovingOrEnditSourcePath(data, subtype, context);
        if (sourcePath.empty()) {
            MEDIA_ERR_LOG("MtpMedialibraryManager::SetObject get sourcePath failed");
            return MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE);
        }
        outObjectInfo->handle = context->handle;
        outObjectInfo->name = display_name;
        outObjectInfo->parent = context->parent;
        outObjectInfo->storageID = context->storageID;
        struct stat statInfo;
        if (stat(sourcePath.c_str(), &statInfo) != 0) {
            MEDIA_ERR_LOG("MtpMedialibraryManager::SetObject stat failed");
            return MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE);
        }
        outObjectInfo->size = GetSizeFromOfft(statInfo.st_size);
        outObjectInfo->dateCreated = statInfo.st_ctime;
        outObjectInfo->dateModified = statInfo.st_mtime;
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_2;
        outObjectInfo->thumbFormat = MTP_FORMAT_EXIF_JPEG_CODE;
        outObjectInfo->thumbPixelHeight = NORMAL_HEIGHT;
        outObjectInfo->thumbPixelWidth = NORMAL_WIDTH;
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    return MtpErrorUtils::SolveGetObjectInfoError(E_SUCCESS);
}

int32_t MtpMedialibraryManager::SetObjectInfo(const unique_ptr<FileAsset> &fileAsset,
    shared_ptr<ObjectInfo> &outObjectInfo)
{
    CHECK_AND_RETURN_RET_LOG(outObjectInfo != nullptr,
        MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR), "outObjectInfo is nullptr");
    outObjectInfo->handle = fileAsset->GetId();
    outObjectInfo->name = fileAsset->GetDisplayName();
    outObjectInfo->size = static_cast<uint32_t>(fileAsset->GetSize()); // need support larger than 4GB file
    outObjectInfo->parent = static_cast<uint32_t>(fileAsset->GetParent());
    outObjectInfo->dateCreated = fileAsset->GetDateAdded();
    outObjectInfo->dateModified = fileAsset->GetDateModified();
    outObjectInfo->storageID = DEFAULT_STORAGE_ID;
    if (fileAsset->GetMediaType() == MEDIA_TYPE_ALBUM) {
        outObjectInfo->format = MTP_FORMAT_ASSOCIATION_CODE;
    } else if (fileAsset->GetMediaType() == MEDIA_TYPE_IMAGE) {
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_1;
        outObjectInfo->format = MTP_FORMAT_EXIF_JPEG_CODE;
        outObjectInfo->storageID = DEFAULT_STORAGE_ID;
        outObjectInfo->imagePixelHeight = static_cast<uint32_t>(fileAsset->GetHeight());
        outObjectInfo->imagePixelWidth = static_cast<uint32_t>(fileAsset->GetWidth());
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_2;
        outObjectInfo->thumbFormat = MTP_FORMAT_EXIF_JPEG_CODE;
        outObjectInfo->thumbPixelHeight = NORMAL_HEIGHT;
        outObjectInfo->thumbPixelWidth = NORMAL_WIDTH;
    } else if (fileAsset->GetMediaType() == MEDIA_TYPE_VIDEO) {
        MEDIA_INFO_LOG("SetObjectInfo MEDIA_TYPE_VIDEO");
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_1;
        outObjectInfo->format = MTP_FORMAT_MPEG_CODE;
        outObjectInfo->storageID = DEFAULT_STORAGE_ID;
        outObjectInfo->imagePixelHeight = static_cast<uint32_t>(fileAsset->GetHeight());
        outObjectInfo->imagePixelWidth = static_cast<uint32_t>(fileAsset->GetWidth());
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_2;
        outObjectInfo->thumbFormat = MTP_FORMAT_EXIF_JPEG_CODE;
        outObjectInfo->thumbPixelHeight = NORMAL_HEIGHT;
        outObjectInfo->thumbPixelWidth = NORMAL_WIDTH;
    }
    return MtpErrorUtils::SolveGetObjectInfoError(E_SUCCESS);
}

int32_t MtpMedialibraryManager::GetFd(const shared_ptr<MtpOperationContext> &context, int32_t &outFd)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr,
        MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "context is nullptr");
    MEDIA_INFO_LOG("GetFd  handle::%{public}u", context->handle);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    if (context->handle < EDITED_PHOTOS_OFFSET) {
        MEDIA_INFO_LOG("ptp photos");
        uint32_t id = context->handle % COMMON_PHOTOS_OFFSET;
        string uri = URI_MTP_OPERATION + "/" + to_string(id);
        MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri openUri(uri);
        outFd = dataShareHelper_->OpenFile(openUri, MEDIA_FILEMODE_READWRITE);
    } else {
        shared_ptr<DataShare::DataShareResultSet> resultSet = GetPhotosInfo(context, false);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
            MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "fail to get handles");
        CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
            MtpErrorUtils::SolveGetFdError(E_SUCCESS), "fail to get fd");
        std::string sourcePath;
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
            int32_t subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
            sourcePath = MtpDataUtils::GetMovingOrEnditSourcePath(data, subtype, context);
        }
        std::string realPath;
        PathToRealPath(sourcePath, realPath);
        MEDIA_INFO_LOG("mtp GetFd realPath %{public}s", realPath.c_str());
        std::error_code ec;
        int mode = sf::exists(realPath, ec) ? O_RDWR : O_RDWR | O_CREAT;
        outFd = open(realPath.c_str(), mode);
    }
    if (outFd > 0) {
        MEDIA_INFO_LOG("mtp GetFd outFd %{public}d", outFd);
        return MtpErrorUtils::SolveGetFdError(E_SUCCESS);
    } else {
        return MtpErrorUtils::SolveGetFdError(E_HAS_FS_ERROR);
    }
}

bool MtpMedialibraryManager::CompressImage(std::unique_ptr<PixelMap> &pixelMap,
    Size &size, std::vector<uint8_t> &data)
{
    InitializationOptions opts = {
        .size = size,
        .pixelFormat = PixelFormat::RGBA_8888,
        .alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL
    };
    unique_ptr<PixelMap> compressImage = PixelMap::Create(*pixelMap, opts);

    PackOption option = {
        .format = THUMBNAIL_FORMAT,
        .quality = THUMBNAIL_MID,
        .numberHint = 1
    };

    data.resize(compressImage->GetByteCount());

    ImagePacker imagePacker;
    uint32_t errorCode = imagePacker.StartPacking(data.data(), data.size(), option);
    if (errorCode != E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }
    errorCode = imagePacker.AddImage(*compressImage);
    if (errorCode != E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }

    int64_t packedSize = 0;
    errorCode = imagePacker.FinalizePacking(packedSize);
    if (errorCode != E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }

    data.resize(packedSize);
    return true;
}

int32_t MtpMedialibraryManager::GetThumb(const shared_ptr<MtpOperationContext> &context,
    shared_ptr<UInt8List> &outThumb)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    MEDIA_INFO_LOG("GetThumb handle::%{public}u", context->handle);
    if (context->handle > COMMON_MOVING_OFFSET) {
        return GetVideoThumb(context, outThumb);
    } else if (context->handle > EDITED_PHOTOS_OFFSET) {
        return GetPictureThumb(context, outThumb);
    }
    shared_ptr<DataShare::DataShareResultSet> resultSet = GetPhotosInfo(context, false);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MTP_ERROR_STORE_NOT_AVAILABLE, "fail to get handles");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        MTP_ERROR_STORE_NOT_AVAILABLE, "have no row");
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    CHECK_AND_RETURN_RET_LOG(fetchFileResult != nullptr,
        MTP_ERROR_INVALID_OBJECTHANDLE, "fetchFileResult is nullptr");
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    MediaType mediaType = fileAsset->GetMediaType();
    if (mediaType == MediaType::MEDIA_TYPE_IMAGE) {
        return GetPictureThumb(context, outThumb);
    } else if (mediaType == MediaType::MEDIA_TYPE_VIDEO) {
        return GetVideoThumb(context, outThumb);
    }
    return MTP_SUCCESS;
}

void MtpMedialibraryManager::CondCloseFd(bool isConditionTrue, const int fd)
{
    if (!isConditionTrue || fd <= 0) {
        return;
    }
    int32_t ret = close(fd);
    if (ret != MTP_SUCCESS) {
        MEDIA_ERR_LOG("DealFd CloseFd fail!");
    }
}

int32_t MtpMedialibraryManager::GetPictureThumb(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<UInt8List> &outThumb)
{
    int fd = 0;
    GetFd(context, fd);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = NORMAL_WIDTH,
        .height = NORMAL_HEIGHT
    };
    std::unique_ptr<PixelMap> cropPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    CHECK_AND_RETURN_RET_LOG(cropPixelMap != nullptr, MTP_ERROR_NO_THUMBNAIL_PRESENT, "PixelMap is nullptr");
    close(fd);
    Size size = {
        .width = NORMAL_WIDTH,
        .height = NORMAL_HEIGHT
    };
    bool ret = CompressImage(cropPixelMap, size, *outThumb);
    CHECK_AND_RETURN_RET_LOG(ret == true, MTP_ERROR_NO_THUMBNAIL_PRESENT, "CompressImage failed");
    return MTP_SUCCESS;
}

int32_t MtpMedialibraryManager::GetVideoThumb(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<UInt8List> &outThumb)
{
    int fd = 0;
    int error = GetFd(context, fd);
    CHECK_AND_RETURN_RET_LOG(error == MTP_SUCCESS, MTP_ERROR_NO_THUMBNAIL_PRESENT, "GetFd failed");
    shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(avMetadataHelper != nullptr,
        MTP_ERROR_NO_THUMBNAIL_PRESENT, "avMetadataHelper is nullptr");
    struct stat64 st;
    int32_t ret = fstat64(fd, &st);
    CondCloseFd(ret != 0, fd);
    CHECK_AND_RETURN_RET_LOG(ret == 0, MTP_ERROR_NO_THUMBNAIL_PRESENT, "Get file state failed, err %{public}d", errno);
    int64_t length = static_cast<int64_t>(st.st_size);
    ret = avMetadataHelper->SetSource(fd, 0, length, AV_META_USAGE_PIXEL_MAP);
    CondCloseFd(ret != 0, fd);
    CHECK_AND_RETURN_RET_LOG(ret == 0, MTP_ERROR_NO_THUMBNAIL_PRESENT, "SetSource failed, ret %{public}d", ret);
    PixelMapParams param;
    param.colorFormat = PixelFormat::RGBA_8888;
    param.dstWidth = NORMAL_WIDTH;
    param.dstHeight = NORMAL_HEIGHT;
    shared_ptr<PixelMap> sPixelMap = avMetadataHelper->FetchFrameYuv(0,
        AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC, param);
    CondCloseFd(sPixelMap == nullptr, fd);
    CHECK_AND_RETURN_RET_LOG(sPixelMap != nullptr, MTP_ERROR_NO_THUMBNAIL_PRESENT, "sPixelMap is nullptr");
    if (sPixelMap->GetPixelFormat() == PixelFormat::YCBCR_P010) {
        uint32_t ret = ImageFormatConvert::ConvertImageFormat(sPixelMap, PixelFormat::RGBA_1010102);
        CondCloseFd(ret != E_OK, fd);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, MTP_ERROR_NO_THUMBNAIL_PRESENT,
            "PixelMapYuv10ToRGBA_1010102: source ConvertImageFormat fail");
    }
    Size size = {
        .width = NORMAL_WIDTH,
        .height = NORMAL_HEIGHT
    };
    InitializationOptions opts = {
        .size = size,
        .pixelFormat = PixelFormat::RGBA_8888,
        .alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL
    };
    unique_ptr<PixelMap> compressImage = PixelMap::Create(*sPixelMap, opts);
    CondCloseFd(sPixelMap == nullptr, fd);
    CHECK_AND_RETURN_RET_LOG(compressImage != nullptr, MTP_ERROR_NO_THUMBNAIL_PRESENT, "compressImage is nullptr");
    CloseFdForGet(context, fd);
    bool retparam = CompressImage(compressImage, size, *outThumb);
    CHECK_AND_RETURN_RET_LOG(retparam == true, MTP_ERROR_NO_THUMBNAIL_PRESENT, "CompressVideo failed");
    return MTP_SUCCESS;
}

int32_t MtpMedialibraryManager::GetAssetById(const int32_t id, shared_ptr<FileAsset> &outFileAsset)
{
    DataShare::DataSharePredicates predicates;
    string whereClause = MEDIA_DATA_DB_ID + " = ?";
    uint32_t field_id = id;
    if (field_id > COMMON_PHOTOS_OFFSET) {
        field_id = id - COMMON_PHOTOS_OFFSET;
    }
    vector<string> whereArgs = {to_string(field_id)};
    predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, POSITION);
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, "0");
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, "0");
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, "0");
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        return E_NO_SUCH_FILE;
    }
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    CHECK_AND_RETURN_RET_LOG(fetchFileResult != nullptr,
        MTP_ERROR_INVALID_OBJECTHANDLE, "fetchFileResult is nullptr");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        E_NO_SUCH_FILE, "no such file");
    unique_ptr<FileAsset> fileUniAsset = fetchFileResult->GetFirstObject();
    outFileAsset = move(fileUniAsset);
    return E_SUCCESS;
}

int32_t MtpMedialibraryManager::GetPathById(const int32_t id, string &outPath)
{
    shared_ptr<FileAsset> fileAsset;
    int errCode = GetAssetById(id, fileAsset);
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_HAS_DB_ERROR, "fileAsset is nullptr, assetId: %{public}d", id);
    outPath = fileAsset->GetPath();
    return errCode;
}

int32_t MtpMedialibraryManager::GetIdByPath(const std::string &path, uint32_t &outId)
{
    DataShare::DataSharePredicates predicates;
    string whereClause = MEDIA_DATA_DB_FILE_PATH + " = ?";
    vector<string> whereArgs = {path};
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        return E_NO_SUCH_FILE;
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MTP_ERROR_STORE_NOT_AVAILABLE, "fail to get handles");
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    CHECK_AND_RETURN_RET_LOG(fetchFileResult != nullptr,
        MTP_ERROR_INVALID_OBJECTHANDLE, "fetchFileResult is nullptr");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        E_NO_SUCH_FILE, "no such file");
    unique_ptr<FileAsset> fileUniAsset = fetchFileResult->GetFirstObject();
    outId = static_cast<uint32_t>(fileUniAsset->GetId());
    return E_SUCCESS;
}

int32_t MtpMedialibraryManager::SendObjectInfo(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outStorageID, uint32_t &outParent, uint32_t &outHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    DataShare::DataShareValuesBucket valuesBucket;
    MediaType mediaType;
    int errCode = MtpDataUtils::SolveSendObjectFormatData(context->format, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, errCode, "fail to SolveSendObjectFormatData");
    if ((mediaType != MEDIA_TYPE_IMAGE && mediaType != MEDIA_TYPE_VIDEO) || context->parent == uint32_t(-1)) {
        MEDIA_ERR_LOG("file type not support");
        return MTP_ERROR_INVALID_OBJECTHANDLE;
    }
    string uri = MEDIALIBRARY_DATA_URI + "/" + PTP_OPERATION + "/" + MEDIA_FILEOPRN_CREATEASSET;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri createFileUri(uri);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, context->name);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    int outRowId = dataShareHelper_->Insert(createFileUri, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(outRowId > 0,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "fail to create assset");
    outHandle = static_cast<uint32_t>(outRowId + COMMON_PHOTOS_OFFSET);
    outStorageID = DEFAULT_STORAGE_ID;
    outParent = context->parent;
    return MtpErrorUtils::SolveSendObjectInfoError(E_SUCCESS);
}

int32_t MtpMedialibraryManager::MoveObject(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    return MtpErrorUtils::SolveCloseFdError(MTP_STORE_READ_ONLY);
}

int32_t CopyNewAssert(const int32_t &fileId, const int32_t &albumId, const string &title,
    uint32_t &outObjectHandle, std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileId);
    valuesBucket.Put(MediaColumn::MEDIA_TITLE, title);
    string cloneUri = URI_MTP_OPERATION + "/" + OPRN_CLONE_ASSET;
    MediaFileUtils::UriAppendKeyValue(cloneUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri cloneAssetUri(cloneUri);
    int32_t insertId = dataShareHelper->Insert(cloneAssetUri, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(insertId >= 0,
        MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR), "fail to clone photo");
    outObjectHandle = insertId + COMMON_PHOTOS_OFFSET;
    string updateOwnerAlbumIdUriStr = URI_MTP_OPERATION + "/" + OPRN_UPDATE_OWNER_ALBUM_ID;
    MediaFileUtils::UriAppendKeyValue(updateOwnerAlbumIdUriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateOwnerAlbumIdUri(updateOwnerAlbumIdUriStr);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(insertId));
    DataShare::DataShareValuesBucket valuesBucketForOwnerAlbumId;
    valuesBucketForOwnerAlbumId.Put(PhotoColumn::MEDIA_TITLE, title);
    valuesBucketForOwnerAlbumId.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
    int32_t changedRows = dataShareHelper->Update(updateOwnerAlbumIdUri, predicates, valuesBucketForOwnerAlbumId);
    return changedRows;
}

int32_t MtpMedialibraryManager::CopyObject(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outObjectHandle)
{
    CHECK_AND_RETURN_RET_LOG((context != nullptr) && (context->parent != 0),
        MTP_ERROR_INVALID_OBJECTHANDLE, "context is invailed");
    CHECK_AND_RETURN_RET_LOG(context->handle > COMMON_PHOTOS_OFFSET, MTP_ERROR_PARAMETER_NOT_SUPPORTED,
        "not allow to copy folder in PTP");
    MediaType mediaType;
    int errCode = MtpDataUtils::SolveSendObjectFormatData(context->format, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, errCode, "fail to SolveSendObjectFormatData");

    int32_t fileId = context->handle - COMMON_PHOTOS_OFFSET;
    string queryUriStr = PAH_QUERY_PHOTO;
    MediaFileUtils::UriAppendKeyValue(queryUriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri queryUri(queryUriStr);
    DataShare::DataSharePredicates idPredicates;
    string whereClause = MEDIA_DATA_DB_ID + " = ?";
    vector<string> whereArgs = {to_string(fileId)};
    idPredicates.SetWhereClause(whereClause);
    idPredicates.SetWhereArgs(whereArgs);
    
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR), "dataShareHelper_ is nullptr");
    vector<string> columns;
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(queryUri, idPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR), "fail to get resultset");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        MtpErrorUtils::SolveCopyObjectError(E_NO_SUCH_FILE), "fail to get data");
    int32_t indexPos = -1;
    resultSet->GetColumnIndex(MediaColumn::MEDIA_TITLE, indexPos);
    string title;
    resultSet->GetString(indexPos, title);
    int32_t changedRows = CopyNewAssert(fileId, static_cast<int32_t>(context->parent),
        title, outObjectHandle, dataShareHelper_);
    CHECK_AND_RETURN_RET_LOG(changedRows >= 0 && changedRows != MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR),
        MtpErrorUtils::SolveCopyObjectError(E_HAS_DB_ERROR), "fail to update photo");
    return MTP_SUCCESS;
}

int32_t MtpMedialibraryManager::DeleteObject(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    return MtpErrorUtils::SolveCloseFdError(MTP_STORE_READ_ONLY);
}

int32_t MtpMedialibraryManager::SetObjectPropValue(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    return MtpErrorUtils::SolveCloseFdError(MTP_STORE_READ_ONLY);
}

int32_t MtpMedialibraryManager::CloseFdForGet(const std::shared_ptr<MtpOperationContext> &context, int32_t fd)
{
    MEDIA_INFO_LOG("CloseFd  handle::%{public}u", context->handle);
    CHECK_AND_RETURN_RET_LOG(fd > 0, E_ERR, "wrong fd");
    int errCode = close(fd);
    return MtpErrorUtils::SolveCloseFdError(errCode);
}

int32_t MtpMedialibraryManager::CloseFd(const shared_ptr<MtpOperationContext> &context, int32_t fd)
{
    MEDIA_INFO_LOG("CloseFd  handle::%{public}u", context->handle);
    int32_t errCode = E_SUCCESS;
    CHECK_AND_RETURN_RET_LOG(fd > 0, E_ERR, "wrong fd");
    if (context->handle > EDITED_PHOTOS_OFFSET) {
        errCode = close(fd);
        return MtpErrorUtils::SolveCloseFdError(errCode);
    }
    shared_ptr<FileAsset> fileAsset;
    errCode = GetAssetById(context->handle, fileAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveCloseFdError(errCode), "fail to GetAssetById");
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, MEDIALIBRARY_DATA_URI + "/" + PTP_OPERATION + "/" + MEDIA_FILEOPRN_CLOSEASSET +
        "/" + to_string(context->handle - COMMON_PHOTOS_OFFSET));
    MEDIA_INFO_LOG("CloseFd %{public}s, FilePath  %{public}s", fileAsset->GetUri().c_str(),
        fileAsset->GetFilePath().c_str());
    Uri closeAssetUri(MEDIALIBRARY_DATA_URI + "/" + PTP_OPERATION + "/" + MEDIA_FILEOPRN_CLOSEASSET);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    if (close(fd) == MTP_SUCCESS) {
        errCode = dataShareHelper_->Insert(closeAssetUri, valuesBucket);
    }
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to Close file");
    DataShare::DataShareValuesBucket valuesBucketForOwnerAlbumId;
    string uri = URI_MTP_OPERATION + "/" + OPRN_UPDATE_OWNER_ALBUM_ID;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateOwnerAlbumIdUri(uri);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(context->handle - COMMON_PHOTOS_OFFSET));
    valuesBucketForOwnerAlbumId.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, static_cast<int32_t>(context->parent));
    int32_t changedRows = dataShareHelper_->Update(updateOwnerAlbumIdUri, predicates, valuesBucketForOwnerAlbumId);
    CHECK_AND_RETURN_RET_LOG(changedRows > 0,
        MtpErrorUtils::SolveCloseFdError(E_HAS_DB_ERROR), "fail to update owneralbumid");
    return MtpErrorUtils::SolveCloseFdError(E_SUCCESS);
}

int32_t MtpMedialibraryManager::GetObjectPropList(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<std::vector<Property>> &outProps)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    if (context->property == 0) {
        if (context->groupCode == 0) {
            MEDIA_ERR_LOG("groupCode error");
            return MTP_ERROR_PARAMETER_NOT_SUPPORTED;
        }
        MEDIA_ERR_LOG("context property = 0");
        return MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED;
    }
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->handle < COMMON_PHOTOS_OFFSET) {
        context->parent = PARENT_ID;
    }
    if (context->parent == PARENT_ID && context->handle < COMMON_PHOTOS_OFFSET) {
        resultSet = GetAlbumInfo(context, false);
    } else {
        resultSet = GetPhotosInfo(context, false);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MTP_ERROR_INVALID_OBJECTHANDLE, "fail to getSet");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        MTP_ERROR_INVALID_OBJECTHANDLE, "have no row");
    return MtpDataUtils::GetPropListBySet(context, resultSet, outProps);
}

int32_t MtpMedialibraryManager::GetObjectPropValue(const shared_ptr<MtpOperationContext> &context,
    uint64_t &outIntVal, uint128_t &outLongVal, string &outStrVal)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->parent == PARENT_ID) {
        resultSet = GetAlbumInfo(context, false);
    } else {
        resultSet = GetPhotosInfo(context, false);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to getSet");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK,
        MTP_ERROR_INVALID_OBJECTHANDLE, "have no row");
    PropertyValue propValue;
    int32_t errCode = MtpDataUtils::GetPropValueBySet(context->property, resultSet, propValue);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to get GetPropValueBySet");
    outIntVal = propValue.outIntVal;
    outStrVal = propValue.outStrVal;
    return errCode;
}

void MtpMedialibraryManager::DeleteCanceledObject(uint32_t id)
{
    if (dataShareHelper_ == nullptr) {
        MEDIA_INFO_LOG("MtpMedialibraryManager::DeleteCanceledObject fail to get datasharehelpe");
    }

    string trashUri = PAH_TRASH_PHOTO;
    MediaFileUtils::UriAppendKeyValue(trashUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri trashAssetUri(trashUri);
    DataShare::DataShareValuesBucket valuesBucketTrashed;
    valuesBucketTrashed.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeMilliSeconds());
    DataShare::DataSharePredicates predicatesTrashed;
    predicatesTrashed.EqualTo(MediaColumn::MEDIA_ID, to_string(id - COMMON_PHOTOS_OFFSET));
    dataShareHelper_->Update(trashAssetUri, predicatesTrashed, valuesBucketTrashed);
    MEDIA_INFO_LOG("Update file date_trashed SUCCESS");

    std::string deleteUriStr = TOOL_DELETE_PHOTO;
    MediaFileUtils::UriAppendKeyValue(deleteUriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri deleteUri(deleteUriStr);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, to_string(id - COMMON_PHOTOS_OFFSET));
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::MEDIA_DATE_TRASHED, DATE_UNTRASHED);
    dataShareHelper_->Update(deleteUri, predicates, valuesBucket);
    MEDIA_INFO_LOG("DeleteCaneledObject SUCCESS");
}

}  // namespace Media
}  // namespace OHOS
