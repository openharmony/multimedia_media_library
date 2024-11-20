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
#include "directory_ex.h"
#include "fetch_result.h"
#include "image_packer.h"
#include "image_source.h"
#include "media_column.h"
#include "mtp_data_utils.h"
#include "media_file_utils.h"
#include "media_mtp_utils.h"
#include "mtp_error_utils.h"
#include "media_log.h"
#include "media_smart_map_column.h"
#include "moving_photo_file_utils.h"
#include "photo_album_column.h"
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
const int32_t POSITION = 2;
const string ISLOCAL = "2";
const int32_t NUMBER_TWO = 2;
const std::string PARENT = "parent";
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
    mediaPhotoAlbumObserver_->context_ = context_;
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
        columns.push_back("album_id as " + MEDIA_DATA_DB_ID);
        columns.push_back("album_name as " + MEDIA_DATA_DB_NAME);
        columns.push_back("7 as " + MEDIA_DATA_DB_MEDIA_TYPE);
        predicates.IsNotNull(MEDIA_DATA_DB_ALBUM_NAME);
        predicates.NotEqualTo(MEDIA_DATA_DB_ALBUM_NAME, ".hiddenAlbum");
        predicates.NotEqualTo(MEDIA_DATA_DB_IS_LOCAL, ISLOCAL);
        resultSet = dataShareHelper_->Query(uri, predicates, columns);
    } else {
        Uri uri(PAH_QUERY_PHOTO);
        columns.push_back("file_id + " + to_string(PHOTES_FILE_ID) + " as " + MEDIA_DATA_DB_ID);
        columns.push_back("size");
        columns.push_back("display_name");
        columns.push_back("owner_album_id as " + PARENT);
        columns.push_back("date_added");
        columns.push_back("duration");
        columns.push_back("media_type");
        columns.push_back("subtype");
        columns.push_back("edit_time");
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
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get GetRowCount");
    // have no handles is not error(maybe it is really have no files)
    CHECK_AND_RETURN_RET_LOG(count > 0,
        MtpErrorUtils::SolveGetHandlesError(E_SUCCESS), "have no handles");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t id = GetInt32Val("file_id", resultSet);
        outHandles.push_back(id);
    }
    resultSet->GoToFirstRow();
    return MtpErrorUtils::SolveGetHandlesError(E_SUCCESS);
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::getAlbumInfo(
    const shared_ptr<MtpOperationContext> &context, bool isHandle)
{
    if (dataShareHelper_ == nullptr) {
        MEDIA_INFO_LOG("MtpMedialibraryManager::getAlbumInfo fail to get datasharehelpe");
        return nullptr;
    }
    DataShare::DataSharePredicates predicates;
    Uri uri(PAH_QUERY_PHOTO_ALBUM);
    vector<string> columns;
    columns.push_back("album_id as " + MEDIA_DATA_DB_ID);
    columns.push_back("album_name as " + MEDIA_DATA_DB_NAME);
    columns.push_back("7 as " + MEDIA_DATA_DB_MEDIA_TYPE);
    predicates.IsNotNull(MEDIA_DATA_DB_ALBUM_NAME);
    predicates.NotEqualTo(MEDIA_DATA_DB_ALBUM_NAME, ".hiddenAlbum");
    predicates.BeginWrap();
    predicates.NotEqualTo(MEDIA_DATA_DB_IS_LOCAL, ISLOCAL);
    predicates.Or();
    predicates.IsNull(MEDIA_DATA_DB_IS_LOCAL);
    predicates.EndWrap();
    if (!isHandle) {
        predicates.EqualTo(MEDIA_DATA_DB_ALBUM_ID, to_string(context->handle));
    }
    return dataShareHelper_->Query(uri, predicates, columns);
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::getPhotosInfo(
    const shared_ptr<MtpOperationContext> &context, bool isHandle)
{
    if (dataShareHelper_ == nullptr) {
        MEDIA_INFO_LOG("MtpMedialibraryManager::getPhotosInfo fail to get datasharehelpe");
        return nullptr;
    }
    Uri uri(PAH_QUERY_PHOTO);
    vector<string> columns;
    columns.push_back("file_id + " + to_string(PHOTES_FILE_ID) + " as " + MEDIA_DATA_DB_ID);
    columns.push_back("size");
    columns.push_back("display_name");
    columns.push_back("owner_album_id as " + PARENT);
    columns.push_back("date_added");
    columns.push_back("duration");
    columns.push_back("media_type");
    columns.push_back("data");
    columns.push_back("subtype");
    columns.push_back("edit_time");
    DataShare::DataSharePredicates predicates;
    if (isHandle) {
        predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(context->parent));
    } else {
        int32_t file_id = context->handle % PHOTES_FILE_ID;
        predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(file_id));
    }
    predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, POSITION);
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, "0");
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, "0");
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, "0");
    return dataShareHelper_->Query(uri, predicates, columns);
}


void MtpMedialibraryManager::HaveMovingPhotesHandle(const shared_ptr<DataShare::DataShareResultSet> resultSet,
    shared_ptr<UInt32List> &outHandles, const uint32_t parent)
{
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t id = GetInt32Val("file_id", resultSet);
        outHandles->push_back(id);
        int32_t subtype = GetInt32Val("subtype", resultSet);
        int32_t editTime = GetInt32Val("edit_time", resultSet);
        MEDIA_INFO_LOG("MtpMedialibraryManager::HaveMovingPhotesHandle subtype:%{public}d, editTime:%{public}d",
            subtype, editTime);
        if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            uint32_t videoId = id + PHOTES_FILE_ID_TWO;
            outHandles->push_back(videoId);
        }
        if (editTime > 0) {
            uint32_t editPhotoId = id + PHOTES_FILE_ID;
            outHandles->push_back(editPhotoId);
        }
        if (editTime >0 && subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            uint32_t editVideoId = id + PHOTES_FILE_ID_THREE;
            outHandles->push_back(editVideoId);
        }
    }
    resultSet->GoToFirstRow();
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
        resultSet = getAlbumInfo(context, true);
    } else {
        resultSet = getPhotosInfo(context, true);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_NO_SUCH_FILE), "fail to get handles");
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get GetRowCount");
    // have no handles is not error(maybe it is really have no files)
    CHECK_AND_RETURN_RET_LOG(count > 0,
        MtpErrorUtils::SolveGetHandlesError(E_SUCCESS), "have no handles");
    HaveMovingPhotesHandle(resultSet, outHandles, context->parent);
    return MtpErrorUtils::SolveGetHandlesError(E_SUCCESS);
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
    if (context->parent == PARENT_ID && context->handle < PHOTES_FILE_ID) {
        resultSet = getAlbumInfo(context, false);
    } else {
        resultSet = getPhotosInfo(context, false);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE), "fail to get object set");
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
        MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR), "fail to get GetRowCount");
    // have no object is an error
    CHECK_AND_RETURN_RET_LOG(count > 0,
        MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE), "have no handle");
    return SetObject(resultSet, context, outObjectInfo);
}

uint32_t MtpMedialibraryManager::GetSizeFromOfft(const off_t &size)
{
    return size > std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max() : size;
}

int32_t MtpMedialibraryManager::SetObject(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
    const shared_ptr<MtpOperationContext> &context, std::shared_ptr<ObjectInfo> &outObjectInfo)
{
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        if (static_cast<int32_t>(context->handle / PHOTES_FILE_ID) < NUMBER_TWO) {
            unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
            unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
            return SetObjectInfo(fileAsset, outObjectInfo);
        }
        string display_name = GetStringVal("display_name", resultSet);
        string data = GetStringVal("data", resultSet);
        int32_t subtype = GetInt32Val("subtype", resultSet);
        string sourcePath = MtpDataUtils::GetMovingOrEnditSourcePath(data, subtype, context);
        if (sourcePath.empty()) {
            MEDIA_ERR_LOG("MtpMedialibraryManager::SetObject get sourcePath failed");
            return MtpErrorUtils::SolveGetObjectInfoError(E_INVALID_PATH);
        }
        outObjectInfo->handle = context->handle;
        outObjectInfo->name = display_name;
        outObjectInfo->parent = context->parent;
        outObjectInfo->storageID = context->storageID;
        struct stat statInfo;
        if (stat(sourcePath.c_str(), &statInfo) != 0) {
            MEDIA_ERR_LOG("MtpMedialibraryManager::SetObject stat failed");
            return MtpErrorUtils::SolveGetObjectInfoError(E_HAS_FS_ERROR);
        }
        outObjectInfo->size = GetSizeFromOfft(statInfo.st_size);
        outObjectInfo->dateCreated = statInfo.st_ctime;
        outObjectInfo->dateModified = statInfo.st_mtime;
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_2;
        outObjectInfo->thumbFormat = MTP_FORMAT_EXIF_JPEG_CODE;
        outObjectInfo->thumbPixelHeight = NORMAL_HEIGHT;
        outObjectInfo->thumbPixelWidth = NORMAL_WIDTH;
    }
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
    MEDIA_INFO_LOG("GetFd  handle::%{public}u", context->handle);
    CHECK_AND_RETURN_RET_LOG(context != nullptr,
        MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "context is nullptr");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    if (context->handle < PHOTES_FILE_ID_TWO) {
        MEDIA_INFO_LOG("ptp photos");
        uint32_t id = context->handle % PHOTES_FILE_ID;
        string uri = URI_MTP_OPERATION + "/" + to_string(id);
        MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri openUri(uri);
        outFd = dataShareHelper_->OpenFile(openUri, MEDIA_FILEMODE_READWRITE);
    } else {
        shared_ptr<DataShare::DataShareResultSet> resultSet = getPhotosInfo(context, false);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
            MtpErrorUtils::SolveGetHandlesError(E_NO_SUCH_FILE), "fail to get handles");
        auto count = 0;
        auto ret = resultSet->GetRowCount(count);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
            MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get GetRowCount");
        // have no handles is not error(maybe it is really have no files)
        CHECK_AND_RETURN_RET_LOG(count > 0,
            MtpErrorUtils::SolveGetHandlesError(E_SUCCESS), "have no handles");
        std::string sourcePath;
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            string data = GetStringVal("data", resultSet);
            int32_t subtype = GetInt32Val("subtype", resultSet);
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
    MEDIA_INFO_LOG("GetThumb handle::%{public}u", context->handle);
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MTP_ERROR_STORE_NOT_AVAILABLE, "fail to get datasharehelper");
    if (context->handle > PHOTES_FILE_ID_THREE && context->handle < PHOTES_FILE_ID_FOUR) {
        return GetVideoThumb(context, outThumb);
    } else if (context->handle > PHOTES_FILE_ID_TWO) {
        return GetPictureThumb(context, outThumb);
    }
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    resultSet = getPhotosInfo(context, false);
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    MediaType mediaType = fileAsset->GetMediaType();
    if (mediaType == MediaType::MEDIA_TYPE_IMAGE) {
        return GetPictureThumb(context, outThumb);
    } else if (mediaType == MediaType::MEDIA_TYPE_VIDEO) {
        return GetVideoThumb(context, outThumb);
    }
    return MTP_SUCCESS;
}

void MtpMedialibraryManager::CondCloseFd(const bool condition, const int fd)
{
    if (!condition || fd <= 0) {
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
    CloseFd(context, fd);
    bool retparam = CompressImage(compressImage, size, *outThumb);
    CHECK_AND_RETURN_RET_LOG(retparam == true, MTP_ERROR_NO_THUMBNAIL_PRESENT, "CompressVideo failed");
    return MTP_SUCCESS;
}

int32_t MtpMedialibraryManager::GetAssetById(const int32_t id, shared_ptr<FileAsset> &outFileAsset)
{
    DataShare::DataSharePredicates predicates;
    string whereClause = MEDIA_DATA_DB_ID + " = ?" ;
    uint32_t field_id = id;
    if (field_id > PHOTES_FILE_ID) {
        field_id = id - PHOTES_FILE_ID;
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
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK || count == 0) {
        MEDIA_ERR_LOG("have no file");
        return E_NO_SUCH_FILE;
    }
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
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK || count == 0) {
        MEDIA_ERR_LOG("have no file");
        return E_NO_SUCH_FILE;
    }
    unique_ptr<FileAsset> fileUniAsset = fetchFileResult->GetFirstObject();
    outId = static_cast<uint32_t>(fileUniAsset->GetId());
    return E_SUCCESS;
}

int32_t MtpMedialibraryManager::SendObjectInfo(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outStorageID, uint32_t &outParent, uint32_t &outHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    int index = 0;
    int changedRows = 0;
    DataShare::DataShareValuesBucket valuesBucket;
    MediaType mediaType;
    int errCode = MtpDataUtils::SolveSendObjectFormatData(context->format, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, errCode, "fail to SolveSendObjectFormatData");
    if ((mediaType != MEDIA_TYPE_IMAGE && mediaType != MEDIA_TYPE_VIDEO) || context->parent == uint32_t(-1)) {
        MEDIA_ERR_LOG("file type not support");
        return MTP_ERROR_INVALID_OBJECTHANDLE;
    }
    string uri = MEDIALIBRARY_DATA_URI + "/" + PTP_OPERATION   + "/"+ MEDIA_FILEOPRN_CREATEASSET;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri createFileUri(uri);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, context->name);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    index = dataShareHelper_->Insert(createFileUri, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucketForOwnerAlbumId;
    uri = PAH_UPDATE_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateOwnerAlbumIdUri(PAH_UPDATE_PHOTO);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(index));
    valuesBucketForOwnerAlbumId.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, static_cast<int32_t>(context->parent));
    changedRows = dataShareHelper_->Update(updateOwnerAlbumIdUri, predicates, valuesBucketForOwnerAlbumId);
    CHECK_AND_RETURN_RET_LOG(changedRows > 0,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "fail to create assset");
    outHandle = static_cast<uint32_t>(index + PHOTES_FILE_ID);
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
    string cloneUri = PAH_CLONE_ASSET;
    MediaFileUtils::UriAppendKeyValue(cloneUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri cloneAssetUri(cloneUri);
    int32_t insertId = dataShareHelper->Insert(cloneAssetUri, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(insertId >= 0,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "fail to clone photo");
    outObjectHandle = insertId + PHOTES_FILE_ID;
    string updateOwnerAlbumIdUriStr = PAH_UPDATE_PHOTO;
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
    CHECK_AND_RETURN_RET_LOG(context->handle > PHOTES_FILE_ID, MTP_ERROR_PARAMETER_NOT_SUPPORTED,
        "not allow to copy folder in PTP");
    MediaType mediaType;
    int errCode = MtpDataUtils::SolveSendObjectFormatData(context->format, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, errCode, "fail to SolveSendObjectFormatData");

    int32_t fileId = context->handle - PHOTES_FILE_ID;
    string queryUriStr = PAH_QUERY_PHOTO;
    MediaFileUtils::UriAppendKeyValue(queryUriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri queryUri(queryUriStr);
    DataShare::DataSharePredicates idPredicates;
    string whereClause = MEDIA_DATA_DB_ID + " = ?" ;
    vector<string> whereArgs = {to_string(fileId)};
    idPredicates.SetWhereClause(whereClause);
    idPredicates.SetWhereArgs(whereArgs);
    
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "dataShareHelper_ is nullptr");
    vector<string> columns;
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(queryUri, idPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "Failed to get resultset");
    int32_t count = 0;
    auto ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "Failed to get resultset row count");
    CHECK_AND_RETURN_RET_LOG(count > 0,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "Failed to get the count of resultSet");
    resultSet->GoToFirstRow();
    int32_t indexPos = -1;
    resultSet->GetColumnIndex(MediaColumn::MEDIA_TITLE, indexPos);
    string title;
    resultSet->GetString(indexPos, title);
    int32_t changedRows = CopyNewAssert(fileId, static_cast<int32_t>(context->parent),
        title, outObjectHandle, dataShareHelper_);
    CHECK_AND_RETURN_RET_LOG(changedRows >= 0,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "fail to update photo");
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

int32_t MtpMedialibraryManager::CloseFd(const shared_ptr<MtpOperationContext> &context, int32_t fd)
{
    MEDIA_INFO_LOG("CloseFd  handle::%{public}u", context->handle);
    int32_t errCode = E_SUCCESS;
    CHECK_AND_RETURN_RET_LOG(fd > 0, E_ERR, "wrong fd");
    if (context->handle > PHOTES_FILE_ID_TWO) {
        errCode = close(fd);
        return MtpErrorUtils::SolveCloseFdError(errCode);
    }
    shared_ptr<FileAsset> fileAsset;
    errCode = GetAssetById(context->handle, fileAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveCloseFdError(errCode), "fail to GetAssetById");
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, MEDIALIBRARY_DATA_URI + "/" + PTP_OPERATION + "/" + MEDIA_FILEOPRN_CLOSEASSET +
        "/" + to_string(context->handle - PHOTES_FILE_ID));
    MEDIA_INFO_LOG("CloseFd %{public}s, FilePath  %{public}s", fileAsset->GetUri().c_str(),
        fileAsset->GetFilePath().c_str());
    Uri closeAssetUri(MEDIALIBRARY_DATA_URI + "/" + PTP_OPERATION + "/" + MEDIA_FILEOPRN_CLOSEASSET);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    if (close(fd) == MTP_SUCCESS) {
        errCode = dataShareHelper_->Insert(closeAssetUri, valuesBucket);
    }
    return MtpErrorUtils::SolveCloseFdError(errCode);
}

int32_t MtpMedialibraryManager::GetObjectPropList(const std::shared_ptr<MtpOperationContext> &context,
    std::shared_ptr<std::vector<Property>> &outProps)
{
    if (context->property == 0) {
        if (context->groupCode == 0) {
            MEDIA_ERR_LOG("groupCode error");
            return MTP_ERROR_PARAMETER_NOT_SUPPORTED;
        }
        MEDIA_ERR_LOG("context property = 0");
        return MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED;
    }
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->handle < PHOTES_FILE_ID) {
        context->parent = PARENT_ID;
    }
    if (context->parent == PARENT_ID && context->handle < PHOTES_FILE_ID) {
        resultSet = getAlbumInfo(context, false);
    } else {
        resultSet = getPhotosInfo(context, false);
    }
    int count = 0;
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to getSet");
    resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count != 0, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to get set count");
    return MtpDataUtils::GetPropListBySet(context, resultSet, outProps);
}

int32_t MtpMedialibraryManager::GetObjectPropValue(const shared_ptr<MtpOperationContext> &context,
    uint64_t &outIntVal, uint128_t &outLongVal, string &outStrVal)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->parent == PARENT_ID) {
        resultSet = getAlbumInfo(context, false);
    } else {
        resultSet = getPhotosInfo(context, false);
    }
    int count = 0;
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to getSet");
    resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count != 0, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to get set count");
    PropertyValue propValue;
    int32_t errCode = MtpDataUtils::GetPropValueBySet(context->property, resultSet, propValue);
    CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to get GetPropValueBySet");
    outIntVal = propValue.outIntVal;
    outStrVal = propValue.outStrVal;
    return errCode;
}

}  // namespace Media
}  // namespace OHOS
