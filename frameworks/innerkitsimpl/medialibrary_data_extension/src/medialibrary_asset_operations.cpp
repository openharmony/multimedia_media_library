/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_asset_operations.h"

#include <algorithm>
#include <dirent.h>
#include <mutex>

#include "directory_ex.h"
#include "file_asset.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "medialibrary_audio_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_notify.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "media_privacy_manager.h"
#include "mimetype_utils.h"
#include "rdb_errno.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "thumbnail_service.h"
#include "userfile_manager_types.h"
#include "value_object.h"
#include "values_bucket.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

mutex g_uniqueNumberLock;

const string DEFAULT_IMAGE_NAME = "IMG_";
const string DEFAULT_VIDEO_NAME = "VID_";
const string DEFAULT_AUDIO_NAME = "AUD_";

int32_t MediaLibraryAssetOperations::HandleInsertOperation(MediaLibraryCommand &cmd)
{
    int errCode = E_ERR;
    switch (cmd.GetOprnType()) {
        case OperationType::CREATE:
            errCode = CreateOperation(cmd);
            break;
        case OperationType::CLOSE:
            errCode = CloseOperation(cmd);
            break;
        default:
            MEDIA_ERR_LOG("unknown operation type %{public}d", cmd.GetOprnType());
            break;
    }
    return errCode;
}

int32_t MediaLibraryAssetOperations::CreateOperation(MediaLibraryCommand &cmd)
{
    // CreateAsset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Create(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Create(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("create asset by FileSysetm_Asset is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::DeleteOperation(MediaLibraryCommand &cmd)
{
    // delete Asset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Delete(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Delete(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("delete asset by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryAssetOperations::QueryOperation(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    // query asset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Query(cmd, columns);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Query(cmd, columns);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return nullptr;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("api9 operation is not finished");
            return nullptr;
        default:
            MEDIA_ERR_LOG("error operation object");
            return nullptr;
    }
}

int32_t MediaLibraryAssetOperations::UpdateOperation(MediaLibraryCommand &cmd)
{
    if (!AssetInputParamVerification::CheckParamForUpdate(cmd)) {
        return E_INVALID_VALUES;
    }
    // todo: check input params
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Update(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Update(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("create asset by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::OpenOperation(MediaLibraryCommand &cmd, const string &mode)
{
    // Open specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Open(cmd, mode);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Open(cmd, mode);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("open by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::CloseOperation(MediaLibraryCommand &cmd)
{
    // Close specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Close(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Close(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("close by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

static bool CheckOprnObject(OperationObject object)
{
    const set<OperationObject> validOprnObjectet = {
        OperationObject::FILESYSTEM_PHOTO,
        OperationObject::FILESYSTEM_AUDIO,
        OperationObject::FILESYSTEM_DOCUMENT
    };
    if (validOprnObjectet.find(object) == validOprnObjectet.end()) {
        MEDIA_ERR_LOG("input OperationObject %{public}d error!", object);
        return false;
    }
    return true;
}

shared_ptr<FileAsset> MediaLibraryAssetOperations::GetFileAssetFromDb(const string &column,
    const string &value, OperationObject oprnObject, const vector<string> &columns, const string &networkId)
{
    if (!CheckOprnObject(oprnObject) || column.empty() || value.empty()) {
        return nullptr;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return nullptr;
    }

    MediaLibraryCommand cmd(oprnObject, OperationType::QUERY, networkId);
    cmd.GetAbsRdbPredicates()->EqualTo(column, value);

    auto absResultSet = rdbStore->Query(cmd, columns);
    if (absResultSet == nullptr) {
        return nullptr;
    }

    auto resultSetBridge = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(absResultSet);
    auto resultSet = make_shared<DataShare::DataShareResultSet>(resultSetBridge);
    auto fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    return shared_ptr<FileAsset>(fetchResult->GetFirstObject().release());
}

shared_ptr<FileAsset> MediaLibraryAssetOperations::GetFileAssetFromDb(AbsPredicates &predicates,
    OperationObject oprnObject, const vector<string> &columns, const string &networkId)
{
    if (!CheckOprnObject(oprnObject)) {
        return nullptr;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return nullptr;
    }

    MediaLibraryCommand cmd(oprnObject, OperationType::QUERY, networkId);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(predicates.GetOrder());

    auto absResultSet = rdbStore->Query(cmd, columns);
    if (absResultSet == nullptr) {
        return nullptr;
    }

    auto resultSetBridge = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(absResultSet);
    auto resultSet = make_shared<DataShare::DataShareResultSet>(resultSetBridge);
    auto fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    return shared_ptr<FileAsset>(fetchResult->GetFirstObject().release());
}

int32_t MediaLibraryAssetOperations::InsertAssetInDb(MediaLibraryCommand &cmd, const FileAsset &fileAsset)
{
    // All values inserted in this function are the base property for files
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    // Fill basic file information into DB
    const string& displayName = fileAsset.GetDisplayName();
    ValuesBucket assetInfo;
    assetInfo.PutInt(MediaColumn::MEDIA_TYPE, fileAsset.GetMediaType());
    assetInfo.PutString(MediaColumn::MEDIA_URI,
        MediaLibraryDataManagerUtils::GetMediaTypeUri(fileAsset.GetMediaType()));
    string extension = ScannerUtils::GetFileExtension(displayName);
    assetInfo.PutString(MediaColumn::MEDIA_MIME_TYPE,
        MimeTypeUtils::GetMimeTypeFromExtension(extension));
    assetInfo.PutString(MediaColumn::MEDIA_FILE_PATH, fileAsset.GetPath());
    if (cmd.GetApi() == MediaLibraryApi::API_OLD) {
        assetInfo.PutString(MediaColumn::MEDIA_RELATIVE_PATH,
            fileAsset.GetRelativePath());
        if (cmd.GetOprnObject() == OperationObject::FILESYSTEM_PHOTO) {
            assetInfo.PutInt(MediaColumn::MEDIA_PARENT_ID, fileAsset.GetAlbumId());
        }
    }
    assetInfo.PutString(MediaColumn::MEDIA_NAME, displayName);
    assetInfo.PutString(MediaColumn::MEDIA_TITLE,
        MediaLibraryDataManagerUtils::GetFileTitle(displayName));
    if (!fileAsset.GetPath().empty() && MediaFileUtils::IsFileExists(fileAsset.GetPath())) {
        return E_FILE_EXIST;
    }
    
    assetInfo.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, cmd.GetBundleName());
    assetInfo.PutString(MediaColumn::MEDIA_DEVICE_NAME, cmd.GetDeviceName());
    cmd.SetValueBucket(assetInfo);

    int64_t outRowId = -1;
    int32_t errCode = rdbStore->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert into db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(outRowId);
}

int32_t MediaLibraryAssetOperations::CheckDisplayNameWithType(const string &displayName, int32_t mediaType)
{
    int32_t ret = MediaFileUtils::CheckDisplayName(displayName);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_INVALID_DISPLAY_NAME, "Check DisplayName failed, "
        "displayName=%{private}s", displayName.c_str());

    string ext = MediaFileUtils::GetExtensionFromPath(displayName);
    CHECK_AND_RETURN_RET_LOG(!ext.empty(), E_INVALID_DISPLAY_NAME, "invalid extension, displayName=%{private}s",
        displayName.c_str());

    auto typeFromExt = MediaFileUtils::GetMediaType(displayName);
    CHECK_AND_RETURN_RET_LOG(typeFromExt == mediaType, E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL,
        "cannot match, mediaType=%{public}d, ext=%{public}s, type from ext=%{public}d",
        mediaType, ext.c_str(), typeFromExt);
    return E_OK;
}

void MediaLibraryAssetOperations::GetAssetRootDir(int32_t mediaType, string &rootDirPath)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_DIR, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(DIRECTORY_DB_MEDIA_TYPE, to_string(mediaType));

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return;
    }
    auto resultSet = rdbStore->Query(cmd, { DIRECTORY_DB_DIRECTORY });
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain file asset from database, mediaType: %{public}d",
            static_cast<int>(mediaType));
        return;
    }

    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        rootDirPath = GetStringVal(DIRECTORY_DB_DIRECTORY, resultSet);
    } else {
        MEDIA_ERR_LOG("Can not Get root dir from resultSet");
    }
}

int32_t MediaLibraryAssetOperations::SetAssetPathInCreate(FileAsset &fileAsset)
{
    if (!fileAsset.GetPath().empty()) {
        return E_OK;
    }
    string extension = MediaFileUtils::GetExtensionFromPath(fileAsset.GetDisplayName());
    string filePath;
    int32_t uniqueId = CreateAssetUniqueId(fileAsset.GetMediaType());
    int32_t errCode = CreateAssetPathById(uniqueId, fileAsset.GetMediaType(), extension, filePath);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d", errCode);
        return errCode;
    }

    // todo: delete DeleteInvalidRowInDb method and Create here

    // filePath can not be empty
    fileAsset.SetPath(filePath);
    return E_OK;
}

int32_t MediaLibraryAssetOperations::DeleteAssetInDb(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        string strRow = cmd.GetOprnFileId();
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow)) {
            MEDIA_ERR_LOG("MediaLibraryAssetOperations DeleteFile: Index not digit, fileIdStr=%{public}s",
                strRow.c_str());
            return E_INVALID_FILEID;
        }
        cmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, strRow);
    }

    int32_t deletedRows = E_HAS_DB_ERROR;
    int32_t result = rdbStore->Delete(cmd, deletedRows);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{public}d.", result);
    }

    return deletedRows;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryAssetOperations::QueryFiles(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return nullptr;
    }

    string fileId = cmd.GetOprnFileId();
    if (cmd.GetAbsRdbPredicates()->GetWhereClause().empty() && !fileId.empty()) {
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, fileId);
    }
    string networkId = cmd.GetOprnDevice();
    if (!networkId.empty()) {
        std::vector<string> devices;
        devices.push_back(networkId);
        cmd.GetAbsRdbPredicates()->InDevices(devices);
    }
    MediaLibraryTracer tracer;
    tracer.Start("QueryFile RdbStore->Query");
    return rdbStore->Query(cmd, columns);
}

bool MediaLibraryAssetOperations::IsContainsValue(ValuesBucket &values, const string &key)
{
    ValueObject value;
    if (values.GetObject(key, value)) {
        return true;
    }
    return false;
}

int32_t MediaLibraryAssetOperations::ModifyAssetInDb(MediaLibraryCommand &cmd)
{
    int32_t errCode = BeginTransaction();
    if (errCode != E_OK) {
        return errCode;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    int32_t rowId = 0;
    int32_t ret = rdbStore->Update(cmd, rowId);
    if (ret < 0 || rowId < 0) {
        MEDIA_ERR_LOG("update path failed, ret=%{public}d", ret);
        return ret;
    }
    errCode = TransactionCommit();
    if (errCode != E_OK) {
        TransactionRollback();
        return errCode;
    }
    return rowId;
}

int32_t MediaLibraryAssetOperations::UpdateAssetPath(MediaLibraryCommand &cmd,
    const shared_ptr<FileAsset> &fileAsset)
{
    ValuesBucket &values = cmd.GetValueBucket();
    ValueObject valueObject;
    string oldPath = fileAsset->GetPath();
    string newPath;
    if (values.GetObject(MediaColumn::MEDIA_FILE_PATH, valueObject)) {
        valueObject.GetString(newPath);
        // todo: check path with type and extensions
    } else {
        // no new path to update
        return E_OK;
    }

    int32_t errCode = MediaFileUtils::ModifyAsset(oldPath, newPath);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Update Photo Path failed, errCode=%{public}d", errCode);
        return errCode;
    }

    int32_t rowId = ModifyAssetInDb(cmd);
    if (rowId < 0) {
        int32_t ret = MediaFileUtils::ModifyAsset(newPath, oldPath);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Resume Photo Path failed, errCode=%{public}d", ret);
            return ret;
        }
        return E_HAS_DB_ERROR;
    }

    return rowId;
}

int32_t MediaLibraryAssetOperations::UpdateFileName(MediaLibraryCommand &cmd,
    const shared_ptr<FileAsset> &fileAsset)
{
    ValuesBucket &values = cmd.GetValueBucket();
    ValueObject valueObject;
    string newTitle;
    string newDisplayName;
    bool containsTitle = false;
    bool containsDisplayName = false;

    if (values.GetObject(MediaColumn::MEDIA_TITLE, valueObject)) {
        valueObject.GetString(newTitle);
        int32_t errCode = MediaFileUtils::CheckTitle(newTitle);
        CHECK_AND_RETURN_RET_LOG(errCode == E_OK, E_INVALID_DISPLAY_NAME,
            "Input title invalid %{private}s, errCode=%{public}d", newTitle.c_str(), errCode);
        containsTitle = true;
    }
    if (values.GetObject(MediaColumn::MEDIA_NAME, valueObject)) {
        valueObject.GetString(newDisplayName);
        int32_t ret = CheckDisplayNameWithType(newDisplayName, fileAsset->GetMediaType());
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Input displayName invalid %{private}s",
            newDisplayName.c_str());
        containsDisplayName = true;
    }

    if ((!containsTitle) && (!containsDisplayName)) {
        // do not need to update
        return E_OK;
    }
    if (containsTitle && containsDisplayName &&
        (MediaLibraryDataManagerUtils::GetFileTitle(newDisplayName) != newTitle)) {
        MEDIA_ERR_LOG("new displayName [%{private}s] and new title [%{private}s] is not same",
            newDisplayName.c_str(), newTitle.c_str());
        return E_INVALID_DISPLAY_NAME;
    }

    if (!containsTitle) {
        values.PutString(MediaColumn::MEDIA_TITLE,
            MediaLibraryDataManagerUtils::GetFileTitle(newDisplayName));
    }
    if (!containsDisplayName) {
        string ext = MediaFileUtils::SplitByChar(fileAsset->GetDisplayName(), '.');
        values.PutString(MediaColumn::MEDIA_NAME, newTitle + "." + ext);
    }
    return E_OK;
}

int32_t MediaLibraryAssetOperations::UpdateFileInDb(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    int32_t updateRows = 0;
    int32_t result = rdbStore->Update(cmd, updateRows);
    if (result != NativeRdb::E_OK || updateRows <= 0) {
        MEDIA_ERR_LOG("Update File failed. Result %{public}d.", result);
        return E_HAS_DB_ERROR;
    }

    return updateRows;
}

static int32_t OpenFile(const string &filePath, const string &mode)
{
    std::string absFilePath;
    if (!PathToRealPath(filePath, absFilePath)) {
        MEDIA_ERR_LOG("Failed to get real path: %{private}s", filePath.c_str());
        return E_ERR;
    }

    return MediaPrivacyManager(absFilePath, mode).Open();
}

static bool CheckMode(const string &mode)
{
    if (mode.empty()) {
        return false;
    }
    if (MEDIA_OPEN_MODES.find(mode) != MEDIA_OPEN_MODES.end()) {
        return true;
    } else {
        MEDIA_ERR_LOG("Input Mode %{public}s is invalid", mode.c_str());
        return false;
    }
}

int32_t MediaLibraryAssetOperations::OpenAsset(const shared_ptr<FileAsset> &fileAsset, const string &mode)
{
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }
    
    string lowerMode = mode;
    transform(lowerMode.begin(), lowerMode.end(), lowerMode.begin(), ::tolower);
    if (!CheckMode(lowerMode)) {
        return E_INVALID_MODE;
    }

    // todo: when Pending == -1, create asset
    string path = MediaFileUtils::UpdatePath(fileAsset->GetPath(), fileAsset->GetUri());
    int32_t fd = OpenFile(path, lowerMode);
    if (fd < 0) {
        MEDIA_ERR_LOG("open file fd %{private}d, errno %{private}d", fd, errno);
        return E_HAS_FS_ERROR;
    }

    if (mode.find(MEDIA_FILEMODE_WRITEONLY) != string::npos) {
        auto watch = MediaLibraryInotify::GetInstance();
        if (watch != nullptr) {
            MEDIA_DEBUG_LOG("enter inotify, path = %{private}s", path.c_str());
            watch->AddWatchList(path, fileAsset->GetUri());
        }
    }
    return fd;
}

int32_t MediaLibraryAssetOperations::CloseAsset(const shared_ptr<FileAsset> &fileAsset)
{
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }

    // remove inotify event since there is close cmd
    auto watch = MediaLibraryInotify::GetInstance();
    if (watch != nullptr) {
        string uri = fileAsset->GetUri();
        watch->RemoveByFileUri(uri, MediaLibraryApi::API_10);
        MEDIA_DEBUG_LOG("watch RemoveByFileUri, uri:%{private}s", uri.c_str());
    }

    string fileId = to_string(fileAsset->GetId());
    string path = fileAsset->GetPath();
    InvalidateThumbnail(fileId, fileAsset->GetMediaType());
    ScanFile(path);
    auto notifyWatch = MediaLibraryNotify::GetInstance();
    if (notifyWatch != nullptr) {
        notifyWatch->Notify(fileAsset);
    }
    return E_OK;
}

void MediaLibraryAssetOperations::InvalidateThumbnail(const string &fileId, int32_t type)
{
    auto thumbnailService = ThumbnailService::GetInstance();
    if (thumbnailService != nullptr) {
        string tableName;
        switch (type) {
            case MediaType::MEDIA_TYPE_IMAGE:
            case MediaType::MEDIA_TYPE_VIDEO: {
                tableName = PhotoColumn::PHOTOS_TABLE;
                break;
            }
            case MediaType::MEDIA_TYPE_AUDIO: {
                tableName = AudioColumn::AUDIOS_TABLE;
                break;
            }
            default: {
                MEDIA_ERR_LOG("Can not match this type %{public}d", type);
                return;
            }
        }
        thumbnailService->InvalidateThumbnail(fileId, tableName);
    }
}

void MediaLibraryAssetOperations::ScanFile(const string &path)
{
    shared_ptr<ScanFileCallback> scanFileCb = make_shared<ScanFileCallback>();
    if (scanFileCb == nullptr) {
        MEDIA_ERR_LOG("Failed to create scan file callback object");
        return ;
    }
    int ret = MediaScannerManager::GetInstance()->ScanFileSync(path, scanFileCb, MediaLibraryApi::API_10);
    if (ret != 0) {
        MEDIA_ERR_LOG("Scan file failed!");
    }
}

int32_t MediaLibraryAssetOperations::BeginTransaction()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return rdbStore->BeginTransaction();
}

int32_t MediaLibraryAssetOperations::TransactionCommit()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return rdbStore->Commit();
}

int32_t MediaLibraryAssetOperations::TransactionRollback()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return rdbStore->RollBack();
}

int32_t MediaLibraryAssetOperations::CreateAssetUniqueId(int32_t type)
{
    string typeString;
    switch (type) {
        case MediaType::MEDIA_TYPE_IMAGE:
            typeString += IMAGE_ASSET_TYPE;
            break;
        case MediaType::MEDIA_TYPE_VIDEO:
            typeString += VIDEO_ASSET_TYPE;
            break;
        case MediaType::MEDIA_TYPE_AUDIO:
            typeString += AUDIO_ASSET_TYPE;
            break;
        default:
            MEDIA_ERR_LOG("This type %{public}d can not get unique id", type);
            return E_INVALID_VALUES;
    }

    const string updateSql = "UPDATE " + ASSET_UNIQUE_NUMBER_TABLE + " SET " + UNIQUE_NUMBER +
        "=" + UNIQUE_NUMBER + "+1" " WHERE " + ASSET_MEDIA_TYPE + "='" + typeString + "';";
    const string querySql = "SELECT " + UNIQUE_NUMBER + " FROM " + ASSET_UNIQUE_NUMBER_TABLE +
        " WHERE " + ASSET_MEDIA_TYPE + "='" + typeString + "';";

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    lock_guard<mutex> lock(g_uniqueNumberLock);
    int32_t errCode = rdbStore->ExecuteSql(updateSql);
    if (errCode < 0) {
        MEDIA_ERR_LOG("execute update unique number failed, ret=%{public}d", errCode);
        return errCode;
    }

    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return GetInt32Val(UNIQUE_NUMBER, resultSet);
}

int32_t MediaLibraryAssetOperations::CreateAssetBucket(int32_t fileId, int32_t &bucketNum)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("input fileId [%{private}d] is invalid", fileId);
        return E_INVALID_FILEID;
    }
    int start = ASSET_DIR_START_NUM;
    int divider = ASSET_DIR_START_NUM;
    while (fileId > start * ASSET_IN_BUCKET_NUM_MAX) {
        divider = start;
        start <<= 1;
    }

    int fileIdRemainder = fileId % divider;
    if (fileIdRemainder == 0) {
        bucketNum = start + fileIdRemainder;
    } else {
        bucketNum = (start - divider) + fileIdRemainder;
    }
    return E_OK;
}

int32_t MediaLibraryAssetOperations::CreateAssetRealName(int32_t fileId, int32_t mediaType,
    const string &extension, string &name)
{
    string fileNumStr = to_string(fileId);
    if (fileId <= ASSET_MAX_COMPLEMENT_ID) {
        size_t fileIdLen = fileNumStr.length();
        fileNumStr = ("00" + fileNumStr).substr(fileIdLen - 1);
    }
    
    string mediaTypeStr;
    switch (mediaType) {
        case MediaType::MEDIA_TYPE_IMAGE:
            mediaTypeStr = DEFAULT_IMAGE_NAME;
            break;
        case MediaType::MEDIA_TYPE_VIDEO:
            mediaTypeStr = DEFAULT_VIDEO_NAME;
            break;
        case MediaType::MEDIA_TYPE_AUDIO:
            mediaTypeStr = DEFAULT_AUDIO_NAME;
            break;
        default:
            MEDIA_ERR_LOG("This mediatype %{public}d can not get real name", mediaType);
            return E_INVALID_VALUES;
    }

    name = mediaTypeStr + to_string(MediaFileUtils::UTCTimeSeconds()) + "_" + fileNumStr + "." + extension;
    return E_OK;
}

static inline int32_t PrepareAssetDir(const string &dirPath)
{
    CHECK_AND_RETURN_RET(!dirPath.empty(), E_INVALID_PATH);
    if (!MediaFileUtils::IsFileExists(dirPath)) {
        bool ret = MediaFileUtils::CreateDirectory(dirPath);
        CHECK_AND_RETURN_RET_LOG(ret, E_CHECK_DIR_FAIL, "Create Dir Failed! dirPath=%{private}s",
            dirPath.c_str());
    }
    return E_OK;
}

int32_t MediaLibraryAssetOperations::CreateAssetPathById(int32_t fileId, int32_t mediaType,
    const string &extension, string &filePath)
{
    string mediaDirPath;
    GetAssetRootDir(mediaType, mediaDirPath);
    if (mediaDirPath.empty()) {
        return E_INVALID_VALUES;
    }

    int32_t bucketNum = 0;
    int32_t errCode = CreateAssetBucket(fileId, bucketNum);
    if (errCode != E_OK) {
        return errCode;
    }

    string realName;
    errCode = CreateAssetRealName(fileId, mediaType, extension, realName);
    if (errCode != E_OK) {
        return errCode;
    }

    string dirPath = ROOT_MEDIA_DIR + mediaDirPath + to_string(bucketNum);
    errCode = PrepareAssetDir(dirPath);
    if (errCode != E_OK) {
        return errCode;
    }

    filePath = dirPath + "/" + realName;
    return E_OK;
}

const std::unordered_map<std::string, std::vector<VerifyFunction>>
    AssetInputParamVerification::UPDATE_VERIFY_PARAM_MAP = {
    { MediaColumn::MEDIA_ID, { Forbidden } },
    { MediaColumn::MEDIA_URI, { Forbidden } },
    { MediaColumn::MEDIA_FILE_PATH, { IsStringNotNull, IsUniqueValue } },
    { MediaColumn::MEDIA_SIZE, { Forbidden } },
    { MediaColumn::MEDIA_TITLE, { IsStringNotNull } },
    { MediaColumn::MEDIA_NAME, { IsStringNotNull } },
    { MediaColumn::MEDIA_TYPE, { Forbidden } },
    { MediaColumn::MEDIA_MIME_TYPE, { Forbidden } },
    { MediaColumn::MEDIA_OWNER_PACKAGE, { Forbidden } },
    { MediaColumn::MEDIA_DEVICE_NAME, { Forbidden } },
    { MediaColumn::MEDIA_THUMBNAIL, { Forbidden } },
    { MediaColumn::MEDIA_DATE_MODIFIED, { Forbidden } },
    { MediaColumn::MEDIA_DATE_ADDED, { Forbidden } },
    { MediaColumn::MEDIA_DATE_TAKEN, { Forbidden } },
    { MediaColumn::MEDIA_TIME_VISIT, { IsInt64 } },
    { MediaColumn::MEDIA_DURATION, { Forbidden } },
    { MediaColumn::MEDIA_TIME_PENDING, { IsInt64, IsUniqueValue } },
    { MediaColumn::MEDIA_IS_FAV, { IsBool, IsUniqueValue } },
    { MediaColumn::MEDIA_DATE_TRASHED, { IsInt64, IsUniqueValue } },
    { MediaColumn::MEDIA_DATE_DELETED, { IsInt64, IsUniqueValue } },
    { MediaColumn::MEDIA_HIDDEN, { IsBool, IsUniqueValue } },
    { MediaColumn::MEDIA_PARENT_ID, { IsInt64, IsBelowApi9 } },
    { MediaColumn::MEDIA_RELATIVE_PATH, { IsString, IsBelowApi9 } },
    { PhotoColumn::PHOTO_ORIENTATION, { Forbidden } },
    { PhotoColumn::PHOTO_LATITUDE, { Forbidden } },
    { PhotoColumn::PHOTO_LONGITUDE, { Forbidden } },
    { PhotoColumn::PHOTO_LCD, { Forbidden } },
    { PhotoColumn::PHOTO_HEIGHT, { Forbidden } },
    { PhotoColumn::PHOTO_WIDTH, { Forbidden } },
    { PhotoColumn::PHOTO_LCD_VISIT_TIME, { IsInt64 } },
    { AudioColumn::AUDIO_ALBUM, { Forbidden } },
    { AudioColumn::AUDIO_ARTIST, { Forbidden } },
    { DocumentColumn::DOCUMENT_LCD, { Forbidden } },
    { DocumentColumn::DOCUMENT_LCD_VISIT_TIME, { IsInt64 } }
};

bool AssetInputParamVerification::CheckParamForUpdate(MediaLibraryCommand &cmd)
{
    ValuesBucket &values = cmd.GetValueBucket();
    map<string, ValueObject> valuesMap;
    values.GetAll(valuesMap);
    for (auto &iter : valuesMap) {
        if (UPDATE_VERIFY_PARAM_MAP.find(iter.first) == UPDATE_VERIFY_PARAM_MAP.end()) {
            MEDIA_ERR_LOG("param [%{public}s] is not allowed", iter.first.c_str());
            return false;
        }
        for (auto &verifyFunc : UPDATE_VERIFY_PARAM_MAP.at(iter.first)) {
            if (!verifyFunc(iter.second, cmd)) {
                MEDIA_ERR_LOG("verify param [%{public}s] failed", iter.first.c_str());
                return false;
            }
        }
    }
    return true;
}

bool AssetInputParamVerification::Forbidden(ValueObject &value, MediaLibraryCommand &cmd)
{
    return false;
}

bool AssetInputParamVerification::IsInt32(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_INT) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsInt64(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_INT) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsBool(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_BOOL) {
        return true;
    }
    if (value.GetType() == ValueObjectType::TYPE_INT) {
        int32_t ret;
        value.GetInt(ret);
        if (ret == 0 || ret == 1) {
            return true;
        }
    }
    return false;
}

bool AssetInputParamVerification::IsString(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_STRING) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsDouble(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_DOUBLE) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsBelowApi9(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (cmd.GetApi() == MediaLibraryApi::API_OLD) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsStringNotNull(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() != ValueObjectType::TYPE_STRING) {
        return false;
    }
    string str;
    value.GetString(str);
    if (str.empty()) {
        return false;
    }
    return true;
}

bool AssetInputParamVerification::IsUniqueValue(ValueObject &value, MediaLibraryCommand &cmd)
{
    // whether this is the unique value in ValuesBucket
    map<string, ValueObject> valuesMap;
    cmd.GetValueBucket().GetAll(valuesMap);
    if (valuesMap.size() != 1) {
        return false;
    }
    return true;
}
} // namespace Media
} // namespace OHOS