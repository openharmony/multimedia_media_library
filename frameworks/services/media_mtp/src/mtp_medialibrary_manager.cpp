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

#include "mtp_medialibrary_manager.h"

#include <unistd.h>
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "fetch_result.h"
#include "image_packer.h"
#include "image_source.h"
#include "mtp_data_utils.h"
#include "media_file_utils.h"
#include "media_mtp_utils.h"
#include "mtp_error_utils.h"
#include "media_log.h"
#include "media_smart_map_column.h"
#include "system_ability_definition.h"

using namespace std;

namespace OHOS {
namespace Media {
constexpr int32_t NORMAL_WIDTH = 256;
constexpr int32_t NORMAL_HEIGHT = 256;
constexpr int32_t COMPRE_SIZE_LEVEL_1 = 256;
constexpr int32_t COMPRE_SIZE_LEVEL_2 = 204800;
const string THUMBNAIL_FORMAT = "image/jpeg";
static constexpr uint8_t THUMBNAIL_MID = 90;
std::shared_ptr<MtpMedialibraryManager> MtpMedialibraryManager::instance_ = nullptr;
std::mutex MtpMedialibraryManager::mutex_;
shared_ptr<DataShare::DataShareHelper> MtpMedialibraryManager::dataShareHelper_ = nullptr;
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
}

int32_t MtpMedialibraryManager::GetHandles(int32_t parentId, vector<int> &outHandles, MediaType mediaType)
{
    DataShare::DataSharePredicates predicates;
    if (mediaType != MEDIA_TYPE_DEFAULT) {
        predicates.EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(parentId));
    } else {
        predicates.EqualTo(MEDIA_DATA_DB_PARENT_ID, to_string(parentId))->And()->EqualTo(MEDIA_DATA_DB_MEDIA_TYPE,
            to_string(mediaType));
    }
    if (dataShareHelper_ == nullptr) {
        return MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR);
    }
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        return MtpErrorUtils::SolveGetHandlesError(E_NO_SUCH_FILE);
    }
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed");
        return MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR);
    } else if (count == 0) {
        MEDIA_ERR_LOG("have no handles");
        return MtpErrorUtils::SolveGetHandlesError(E_SUCCESS);
    }
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    for (int32_t row = 0; row < count; row++) {
        unique_ptr<FileAsset> fileAsset = fetchFileResult->GetObjectAtPosition(row);
        outHandles.push_back(fileAsset->GetId());
    }
    return MtpErrorUtils::SolveGetHandlesError(E_SUCCESS);
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
    DataShare::DataSharePredicates predicates;
    string whereClause;
    vector<string> whereArgs;
    if (mediaType == MEDIA_TYPE_DEFAULT) {
        whereClause = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_NAME + " Like ? AND " +
            MEDIA_DATA_DB_DATE_TRASHED + " = 0 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " != ?";
        whereArgs = {to_string(context->parent), extension, to_string(MEDIA_TYPE_NOFILE)};
    } else if (mediaType == MEDIA_TYPE_ALL) {
        whereClause = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_DATE_TRASHED +
            " = 0 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " != ?" ;
        whereArgs = {to_string(context->parent), to_string(MEDIA_TYPE_NOFILE)};
    } else {
        whereClause = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " +
            MEDIA_DATA_DB_DATE_TRASHED + " = 0";
        whereArgs = {to_string(context->parent), to_string(mediaType)};
    }
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveGetHandlesError(E_NO_SUCH_FILE), "fail to get handles");
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
        MtpErrorUtils::SolveGetHandlesError(E_HAS_DB_ERROR), "fail to get GetRowCount");
    // have no handles is not error(maybe it is really have no files)
    CHECK_AND_RETURN_RET_LOG(count > 0,
        MtpErrorUtils::SolveGetHandlesError(E_SUCCESS), "have no handles");
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    while (fileAsset != nullptr) {
        outHandles->push_back(fileAsset->GetId());
        fileAsset = fetchFileResult->GetNextObject();
    }
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
    string whereClause = MEDIA_DATA_DB_ID + " = ? AND " + MEDIA_DATA_DB_DATE_TRASHED + " = 0";
    vector<string> whereArgs = {to_string(context->handle)};
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr,
        MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE), "fail to get object set");
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
        MtpErrorUtils::SolveGetObjectInfoError(E_HAS_DB_ERROR), "fail to get GetRowCount");
    // have no object is an error
    CHECK_AND_RETURN_RET_LOG(count > 0,
        MtpErrorUtils::SolveGetObjectInfoError(E_NO_SUCH_FILE), "have no handle");
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    return SetObjectInfo(fileAsset, outObjectInfo);
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
        outObjectInfo->imagePixHeight = static_cast<uint32_t>(fileAsset->GetHeight());
        outObjectInfo->imagePixWidth = static_cast<uint32_t>(fileAsset->GetWidth());
        outObjectInfo->thumbCompressedSize = COMPRE_SIZE_LEVEL_2;
        outObjectInfo->thumbFormat = MTP_FORMAT_EXIF_JPEG_CODE;
        outObjectInfo->thumbPixHeight = NORMAL_HEIGHT;
        outObjectInfo->thumbPixWidth = NORMAL_WIDTH;
    }
    return MtpErrorUtils::SolveGetObjectInfoError(E_SUCCESS);
}

int32_t MtpMedialibraryManager::GetFd(const shared_ptr<MtpOperationContext> &context, int32_t &outFd)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr,
        MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "context is nullptr");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MtpErrorUtils::SolveGetFdError(E_HAS_DB_ERROR), "fail to get datasharehelper");
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + to_string(context->handle));
    outFd = dataShareHelper_->OpenFile(uri, MEDIA_FILEMODE_READWRITE);
    if (outFd > 0) {
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
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }
    errorCode = imagePacker.AddImage(*compressImage);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }

    int64_t packedSize = 0;
    errorCode = imagePacker.FinalizePacking(packedSize);
    if (errorCode != Media::SUCCESS) {
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
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr,
        MTP_ERROR_STORE_NOT_AVAILABLE, "fail to get datasharehelper");
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
    CompressImage(cropPixelMap, size, *outThumb);
    return MTP_SUCCESS;
}

int32_t MtpMedialibraryManager::GetAssetById(const int32_t id, shared_ptr<FileAsset> &outFileAsset)
{
    DataShare::DataSharePredicates predicates;
    string whereClause = MEDIA_DATA_DB_ID + " = ? AND " + MEDIA_DATA_DB_DATE_TRASHED + " = 0";
    vector<string> whereArgs = {to_string(id)};
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    if (dataShareHelper_ == nullptr) {
        return E_HAS_DB_ERROR;
    }
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
    string whereClause = MEDIA_DATA_DB_FILE_PATH + " = ? OR " + MEDIA_DATA_DB_RECYCLE_PATH + " = ?";
    vector<string> whereArgs = {path, path};
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    if (dataShareHelper_ == nullptr) {
        return E_HAS_DB_ERROR;
    }
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
    shared_ptr<FileAsset> fileAsset;
    int errCode = GetAssetById(context->parent, fileAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveSendObjectInfoError(errCode), "fail to GetAssetById");
    int index = 0;
    DataShare::DataShareValuesBucket valuesBucket;
    if (context->format == MTP_FORMAT_ASSOCIATION_CODE) {
        Uri mkdirUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR + MEDIA_DIROPRN_FMS_CREATEDIR);
        valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath() +
            fileAsset->GetDisplayName() + "/" + context->name + "/");
        index = dataShareHelper_->Insert(mkdirUri, valuesBucket);
    } else {
        MediaType mediaType;
        errCode = MtpDataUtils::SolveSendObjectFormatData(context->format, mediaType);
        CHECK_AND_RETURN_RET_LOG(errCode == MTP_SUCCESS, errCode, "fail to SolveSendObjectFormatData");
        Uri createFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
        valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH,
            fileAsset->GetRelativePath() + fileAsset->GetDisplayName() + "/");
        valuesBucket.Put(MEDIA_DATA_DB_NAME, context->name);
        valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
        index = dataShareHelper_->Insert(createFileUri, valuesBucket);
    }
    CHECK_AND_RETURN_RET_LOG(index > 0,
        MtpErrorUtils::SolveSendObjectInfoError(E_HAS_DB_ERROR), "fail to create assset");
    outHandle = static_cast<uint32_t>(index);
    outStorageID = DEFAULT_STORAGE_ID;
    outParent = context->parent;
    return MtpErrorUtils::SolveSendObjectInfoError(E_SUCCESS);
}

int32_t MtpMedialibraryManager::MoveObject(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + std::to_string(context->handle));
    DataShare::DataShareValuesBucket valuesBucket;
    shared_ptr<FileAsset> parentFileAsset;
    int errCode = GetAssetById(context->parent, parentFileAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveMoveObjectError(errCode), "fail to GetAssetById");
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH,
        parentFileAsset->GetRelativePath() + parentFileAsset->GetDisplayName() + "/");
    shared_ptr<FileAsset> fileAsset;
    errCode = GetAssetById(context->handle, fileAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveMoveObjectError(errCode), "fail to GetAssetById");
    valuesBucket.Put(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucket.Put(MEDIA_DATA_DB_ID, static_cast<int32_t>(context->handle));
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
    Uri updateAssetUri(Media::MEDIALIBRARY_DATA_URI + "/" +
        Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET);
    int changedRows = dataShareHelper_->Update(updateAssetUri, predicates, valuesBucket);
    return (changedRows > 0) ? MTP_SUCCESS : MtpErrorUtils::SolveMoveObjectError(changedRows);
}

int32_t MtpMedialibraryManager::CopyObject(const std::shared_ptr<MtpOperationContext> &context,
    uint32_t &outObjectHandle)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "context is nullptr");
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + std::to_string(context->handle));
    shared_ptr<FileAsset> parentAsset;
    int errCode = GetAssetById(context->parent, parentAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveCopyObjectError(errCode), "fail to GetAssetById");
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH,
        parentAsset->GetRelativePath() + parentAsset->GetDisplayName() + "/");
    valuesBucket.Put(MEDIA_DATA_DB_ID, static_cast<int32_t>(context->handle));
    Uri copyAssetUri(Media::MEDIALIBRARY_DATA_URI +
        "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_COPYASSET);
    int changedRows = dataShareHelper_->Insert(copyAssetUri, valuesBucket);
    outObjectHandle = static_cast<uint32_t>(changedRows);
    return (changedRows > 0) ? MTP_SUCCESS : MtpErrorUtils::SolveCopyObjectError(changedRows);
}

int32_t MtpMedialibraryManager::DeleteObject(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_STORE_NOT_AVAILABLE, "context is nullptr");
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, static_cast<int32_t>(context->handle));
    Uri addAsseturi(MEDIALIBRARY_DATA_URI + "/" +
        MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    int changedRows = dataShareHelper_->Insert(addAsseturi, valuesBucket);
    return (changedRows > 0) ? MTP_SUCCESS : MtpErrorUtils::SolveCopyObjectError(changedRows);
}

int32_t MtpMedialibraryManager::SetObjectPropValue(const std::shared_ptr<MtpOperationContext> &context)
{
    CHECK_AND_RETURN_RET_LOG(context != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "context is nullptr");
    string colName;
    variant<int64_t, string> colValue;
    int32_t errCode = MtpDataUtils::SolveSetObjectPropValueData(context, colName, colValue);
    CHECK_AND_RETURN_RET_LOG(errCode == 0, errCode, "fail to SolveSetObjectPropValueData");
    DataShare::DataShareValuesBucket valuesBucket;
    shared_ptr<FileAsset> fileAsset;
    errCode = GetAssetById(context->handle, fileAsset);
    string displayName;
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveObjectPropValueError(errCode), "fail to GetAssetById");
    if (colName.compare(MEDIA_DATA_DB_PARENT_ID) == 0) {
        shared_ptr<FileAsset> parentFileAsset;
        errCode = GetAssetById(get<int64_t>(colValue), parentFileAsset);
        CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
            MtpErrorUtils::SolveObjectPropValueError(errCode), "fail to GetAssetById");
        valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH,
            parentFileAsset->GetRelativePath() + parentFileAsset->GetDisplayName() + "/");
        valuesBucket.Put(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
        displayName = fileAsset->GetDisplayName();
    } else {
        valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
        if (!get<string>(colValue).empty()) {
            displayName = get<string>(colValue);
            valuesBucket.Put(colName, get<string>(colValue));
            valuesBucket.Put(MEDIA_DATA_DB_TITLE, get<string>(colValue));
        } else {
            valuesBucket.Put(colName, get<int64_t>(colValue));
        }
    }
    MediaType mediaType;
    MtpDataUtils::GetMediaTypeByName(displayName, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_ID, static_cast<int32_t>(context->handle));
    string operationCode = (mediaType != MEDIA_TYPE_ALBUM) ? Media::MEDIA_FILEOPRN : Media::MEDIA_ALBUMOPRN;
    Uri updateAssetUri(Media::MEDIALIBRARY_DATA_URI +
        "/" + operationCode + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + std::to_string(context->handle));
    int changedRows = dataShareHelper_->Update(updateAssetUri, predicates, valuesBucket);
    return (changedRows > 0) ? MTP_SUCCESS : MtpErrorUtils::SolveObjectPropValueError(changedRows);
}

int32_t MtpMedialibraryManager::CloseFd(const shared_ptr<MtpOperationContext> &context, int32_t fd)
{
    shared_ptr<FileAsset> fileAsset;
    int32_t errCode = GetAssetById(context->handle, fileAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS,
        MtpErrorUtils::SolveCloseFdError(errCode), "fail to GetAssetById");
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, fileAsset->GetUri());
    Uri closeAssetUri(URI_CLOSE_FILE);
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
    if (context->depth == MTP_ALL_DEPTH && (context->handle == 0 || context->handle == MTP_ALL_HANDLE_ID)) {
        context->handle = MTP_ALL_HANDLE_ID;
        context->depth = 0;
    }
    if (!(context->depth == 0 || context->depth == 1)) {
        MEDIA_ERR_LOG("depth error");
        return MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED;
    }
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->handle != 0) {
        // Add the requested object if format matches
        if (context->depth == 0) {
            if (context->handle == MTP_ALL_HANDLE_ID) {
                // get root dirs children deep : all:success
                resultSet = GetAllRootsChildren(context->format);
            } else {
                // get handle:success
                resultSet = GetHandle(context->format, context->handle);
            }
        }
        if (context->depth == 1) {
            if (context->handle == MTP_ALL_HANDLE_ID) {
                // get root dirs children deep : 1:success
                resultSet = GetRootsDepthChildren(context->format);
            } else {
                // get handle children and handle deep : 1
                resultSet = GetHandleDepthChildren(context->format,  context->handle);
            }
        }
    } else {
        // get root dirs children deep : 1:success
        resultSet = GetRootsDepthChildren(context->format);
    }
    int count = 0;
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to getSet");
    resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count != 0, MTP_ERROR_INVALID_OBJECTHANDLE, "fail to get set count");
    return MtpDataUtils::GetPropListBySet(context->property, context->format, resultSet, outProps);
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::GetAllRootsChildren(const uint16_t format)
{
    DataShare::DataSharePredicates predicates;
    MediaType mediaType;
    MtpDataUtils::GetMediaTypeByformat(format, mediaType);
    string whereClause;
    vector<string> whereArgs;
    if (mediaType == MEDIA_TYPE_ALL) {
        whereClause = MEDIA_DATA_DB_DATE_TRASHED + " = ?";
        whereArgs = {to_string(0)};
    } else {
        whereClause = MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " + MEDIA_DATA_DB_DATE_TRASHED + " = ?";
        whereArgs = {to_string(mediaType), to_string(0)};
    }
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    return dataShareHelper_->Query(uri, predicates, columns);
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::GetHandle(const uint16_t format,
    const uint32_t handle)
{
    DataShare::DataSharePredicates predicates;
    MediaType mediaType;
    MtpDataUtils::GetMediaTypeByformat(format, mediaType);
    string whereClause;
    vector<string> whereArgs;
    if (mediaType == MEDIA_TYPE_ALL) {
        whereClause = MEDIA_DATA_DB_ID + " = ? AND " + MEDIA_DATA_DB_DATE_TRASHED + " = ?";
        whereArgs = {to_string(handle), to_string(0)};
    } else {
        whereClause = MEDIA_DATA_DB_ID + " = ? AND " +
            MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " + MEDIA_DATA_DB_DATE_TRASHED + " = ?";
        whereArgs = {to_string(handle), to_string(mediaType), to_string(0)};
    }
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    return dataShareHelper_->Query(uri, predicates, columns);
}

int32_t MtpMedialibraryManager::GetRootIdList(std::vector<string> &outRootIdList)
{
    DataShare::DataSharePredicates predicates;
    string whereClause;
    vector<string> whereArgs = {to_string(0)};
    whereClause = MEDIA_DATA_DB_PARENT_ID + " = ?";
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper_->Query(uri, predicates, columns);
    auto count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK || count == 0) {
        MEDIA_ERR_LOG("have no file");
        return E_NO_SUCH_FILE;
    }
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
    for (int32_t row = 0; row < count; row++) {
        unique_ptr<FileAsset> fileAsset = fetchFileResult->GetObjectAtPosition(row);
        outRootIdList.push_back(to_string(fileAsset->GetId()));
    }
    return E_SUCCESS;
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::GetRootsDepthChildren(const uint16_t format)
{
    vector<string> rootIdList;
    int errCode = GetRootIdList(rootIdList);
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS, nullptr, "fail to GetRootIdList");
    string whereClause;
    for (size_t row = 0; row < rootIdList.size(); row++) {
        if (row == 0) {
            whereClause = MEDIA_DATA_DB_PARENT_ID + " = ?";
        } else {
            whereClause = whereClause + " OR " + MEDIA_DATA_DB_PARENT_ID + " = ?";
        }
    }
    whereClause = whereClause + " AND " + MEDIA_DATA_DB_MEDIA_TYPE + " = ?";
    MediaType mediaType;
    MtpDataUtils::GetMediaTypeByformat(format, mediaType);
    rootIdList.push_back(to_string(mediaType));
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(rootIdList);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    return dataShareHelper_->Query(uri, predicates, columns);
}

shared_ptr<DataShare::DataShareResultSet> MtpMedialibraryManager::GetHandleDepthChildren(const uint16_t format,
    const uint32_t handle)
{
    DataShare::DataSharePredicates predicates;
    MediaType mediaType;
    MtpDataUtils::GetMediaTypeByformat(format, mediaType);
    string whereClause;
    vector<string> whereArgs;
    if (mediaType == MEDIA_TYPE_ALL) {
        whereClause =  "("+ MEDIA_DATA_DB_ID + " = ? OR " + MEDIA_DATA_DB_PARENT_ID +
            " = ? ) AND " + MEDIA_DATA_DB_DATE_TRASHED + " = ?";
        whereArgs = {to_string(handle), to_string(handle), to_string(0)};
    } else {
        whereClause = "("+ MEDIA_DATA_DB_ID + " = ? OR " + MEDIA_DATA_DB_PARENT_ID +
            " = ? ) AND " + MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " + MEDIA_DATA_DB_DATE_TRASHED + " = ?";
        whereArgs = {to_string(handle), to_string(handle), to_string(mediaType), to_string(0)};
    }
    predicates.SetWhereClause(whereClause);
    predicates.SetWhereArgs(whereArgs);
    Uri uri(MEDIALIBRARY_DATA_URI);
    vector<string> columns;
    return dataShareHelper_->Query(uri, predicates, columns);
}

int32_t MtpMedialibraryManager::GetObjectPropValue(const shared_ptr<MtpOperationContext> &context,
    uint64_t &outIntVal, uint128_t &outLongVal, string &outStrVal)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet = GetHandle(0, context->handle);
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
