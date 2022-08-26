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
#define MLOG_TAG "DirOperation"

#include "medialibrary_dir_operations.h"
#include "abs_rdb_predicates.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "media_log.h"
#include "medialibrary_file_operations.h"
#include "media_file_utils.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_object_utils.h"
#include "rdb_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
static const std::string MEDIA_NO_FILE = ".nofile";

int32_t MediaLibraryDirOperations::DeleteDirInfoUtil(const int &parent,
    const shared_ptr<RdbStore> &rdbStore,
    const MediaLibraryDirDb &dirDbOprn)
{
    shared_ptr<AbsSharedResultSet> queryResultSet, queryParentResultSet;
    vector<string> columns, selectionArgs;
    selectionArgs.push_back(to_string(parent));
    AbsRdbPredicates mediaLibDirAbsPred(MEDIALIBRARY_TABLE);
    mediaLibDirAbsPred.SetWhereClause(DIR_PARENT_WHERECLAUSE);
    mediaLibDirAbsPred.SetWhereArgs(selectionArgs);
    queryResultSet = rdbStore -> Query(mediaLibDirAbsPred, columns);
    int32_t deleteErrorCode = E_FAIL;
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    MEDIA_INFO_LOG("count = %{public}d", (int)count);
    if (count == 0) {
        AbsRdbPredicates mediaLibParentDirAbsPred(MEDIALIBRARY_TABLE);
        mediaLibParentDirAbsPred.SetWhereClause(DIR_FILE_WHERECLAUSE);
        mediaLibParentDirAbsPred.SetWhereArgs(selectionArgs);
        queryParentResultSet = rdbStore->Query(mediaLibParentDirAbsPred, columns);
        if (queryParentResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexParentId, parentIdVal, columnIndexDir;
            string dirVal;
            queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, columnIndexParentId);
            queryParentResultSet->GetInt(columnIndexParentId, parentIdVal);
            queryParentResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndexDir);
            queryParentResultSet->GetString(columnIndexDir, dirVal);
            if (parentIdVal == 0) {
                return E_SUCCESS;
            }
            MEDIA_INFO_LOG("dirVal = %{private}s", dirVal.c_str());
            MEDIA_INFO_LOG("parentIdVal = %{public}d", parentIdVal);
            deleteErrorCode = const_cast<MediaLibraryDirDb &>(dirDbOprn)
                .DeleteDirInfo(parent, rdbStore);
            if (deleteErrorCode != E_SUCCESS) {
                MEDIA_ERR_LOG("rdbstore delete failed");
                return deleteErrorCode;
            }
            if (!MediaFileUtils::DeleteDir(dirVal)) {
                MEDIA_ERR_LOG("deleteDir failed");
                return E_DELETE_DIR_FAIL;
            }
            DeleteDirInfoUtil(parentIdVal, rdbStore, dirDbOprn);
        }
    } else {
        return E_SUCCESS;
    }
    return deleteErrorCode;
}

int32_t MediaLibraryDirOperations::DeleteFMSDirInfoUtil(const std::string &relativePath,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const MediaLibraryDirDb &dirDbOprn)
{
    shared_ptr<AbsSharedResultSet> queryResultSet;
    vector<string> columns, selectionArgs;
    int32_t deleteErrorCode = E_FAIL;
    MEDIA_INFO_LOG("relativePath = %{private}s", relativePath.c_str());
    string data = ROOT_MEDIA_DIR + relativePath;
    if (data.substr(data.length() - 1) == "/") {
        data = data.substr(0, data.length() - 1);
    }
    MEDIA_INFO_LOG("data = %{private}s", data.c_str());
    AbsRdbPredicates mediaLibParentDirAbsPred(MEDIALIBRARY_TABLE);
    selectionArgs.push_back((relativePath + "%"));
    selectionArgs.push_back(data);
    mediaLibParentDirAbsPred.SetWhereClause(DIR_RELATIVEPATH_WHERECLAUSE);
    mediaLibParentDirAbsPred.SetWhereArgs(selectionArgs);
    queryResultSet = rdbStore->Query(mediaLibParentDirAbsPred, columns);
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexId, idVal, columnIndexParentId, parentIdVal;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
        queryResultSet->GetInt(columnIndexId, idVal);
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_PARENT_ID, columnIndexParentId);
        queryResultSet->GetInt(columnIndexParentId, parentIdVal);
        MEDIA_INFO_LOG("DeleteFMSDirInfoUtil idVal = %{public}d", idVal);
        MEDIA_INFO_LOG("DeleteFMSDirInfoUtil parentIdVal = %{public}d", parentIdVal);
        if (parentIdVal == 0) {
            MEDIA_INFO_LOG("Root dir can not delete");
            return E_SUCCESS;
        }
        deleteErrorCode = const_cast<MediaLibraryDirDb &>(dirDbOprn)
                              .DeleteDirInfo(idVal, rdbStore);
        if (!MediaFileUtils::DeleteDir(data)) {
            return E_DELETE_DIR_FAIL;
        } else {
            DeleteDirInfoUtil(parentIdVal, rdbStore, dirDbOprn);
        }
    }
    return deleteErrorCode;
}

bool MediaLibraryDirOperations::CheckMediaTypeMatchExtension(int mediaType, string extensions)
{
    size_t mediaTypeImageIndex, mediaTypeVideoIndex, mediaTypeAudioIndex;
    mediaTypeImageIndex = DIR_ALL_IMAGE_CONTAINER_TYPE.find(extensions);
    mediaTypeVideoIndex = DIR_ALL_VIDEO_CONTAINER_TYPE.find(extensions);
    mediaTypeAudioIndex = DIR_ALL_AUDIO_CONTAINER_TYPE.find(extensions);
    switch (mediaType) {
        case MEDIA_TYPE_FILE:
            if (extensions.empty() || (mediaTypeImageIndex == string::npos
                && mediaTypeVideoIndex == string::npos && mediaTypeAudioIndex == string::npos)) {
                return true;
            } else {
                MEDIA_ERR_LOG("Check CheckMediaTypeMatchExtension file failed");
                return false;
            }
        case MEDIA_TYPE_IMAGE:
            if (mediaTypeImageIndex != string::npos) {
                return true;
            } else {
                MEDIA_ERR_LOG("Check CheckMediaTypeMatchExtension image failed");
                return false;
            }
        case MEDIA_TYPE_VIDEO:
            if (mediaTypeVideoIndex != string::npos) {
                return true;
            } else {
                MEDIA_ERR_LOG("Check CheckMediaTypeMatchExtension video failed");
                return false;
            }
        case MEDIA_TYPE_AUDIO:
            if (mediaTypeAudioIndex != string::npos) {
                return true;
            } else {
                MEDIA_ERR_LOG("Check CheckMediaTypeMatchExtension audio failed");
                return false;
            }
        default:
            MEDIA_ERR_LOG("Check CheckMediaTypeMatchExtension failed, mediaType is undefind");
            return false;
    }
}

bool MediaLibraryDirOperations::CheckMediaType(string mediaTypes, int mediaType)
{
    MEDIA_INFO_LOG("Check mediaType mediaTypes = %{public}s", mediaTypes.c_str());
    MEDIA_INFO_LOG("Check mediaType mediaType = %{public}d", mediaType);
    if (mediaTypes.compare(DIR_ALL_TYPE_VALUES) == 0) {
        MEDIA_INFO_LOG("Check mediaType all type");
        return true;
    }
    size_t mediaTypeIndex = mediaTypes.find(to_string(mediaType));
    if (mediaTypeIndex != string::npos) {
        return true;
    } else {
        MEDIA_ERR_LOG("Check mediaType failed");
        return false;
    }
}

bool MediaLibraryDirOperations::CheckFileExtension(const unordered_map<string, DirAsset> &dirQuerySetMap,
    string extension)
{
    bool isFileExtension = true;
    for (auto &[_, dirAsset] : dirQuerySetMap) {
        if (dirAsset.GetDirType() == DIR_VIDEO ||
            dirAsset.GetDirType() == DIR_PICTURE ||
            dirAsset.GetDirType() == DIR_AUDIOS) {
            size_t extensionIndex = dirAsset.GetExtensions().find(extension);
            if (extensionIndex != string::npos) {
                isFileExtension = false;
            }
        }
    }
    return isFileExtension;
}
bool MediaLibraryDirOperations::CheckExtension(string extensions, string extension)
{
    MEDIA_INFO_LOG("Check mediaType extensions = %{public}s", extensions.c_str());
    MEDIA_INFO_LOG("Check mediaType extension = %{public}s", extension.c_str());
    if (extensions.compare(DIR_ALL_CONTAINER_TYPE) == 0) {
        MEDIA_INFO_LOG("Check extension all type");
        return true;
    }
    size_t extensionIndex = extensions.find(extension);
    if (extensionIndex != string::npos) {
        return true;
    } else {
        MEDIA_ERR_LOG("Check extension failed");
        return false;
    }
}

DirAsset MediaLibraryDirOperations::GetDirQuerySet(const NativeRdb::ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    string rootDir;
    ValueObject valueObject;
    DirAsset dirAsset;
    vector<string> columns, selectionArgs;
    if (values.GetObject(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, valueObject)) {
        valueObject.GetString(rootDir);
        selectionArgs.push_back(rootDir);
    }
    unordered_map<string, DirAsset>::const_iterator iterator = dirQuerySetMap.find(rootDir);
    if (iterator != dirQuerySetMap.end()) {
        MEDIA_INFO_LOG("find in dirQuerySetMap");
        dirAsset = dirQuerySetMap.at(rootDir);
    }
    return dirAsset;
}

int32_t MediaLibraryDirOperations::CheckDirInfoUtil(const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    ValueObject valueObject;
    shared_ptr<AbsSharedResultSet> queryResultSet;
    DirAsset dirAsset;
    string extension, path, extensionVal, mediaTypeVal;
    int mediaType;
    dirAsset = GetDirQuerySet(values, rdbStore, dirQuerySetMap);
    if (dirAsset.GetDirType() == DEFAULT_DIR_TYPE) {
        MEDIA_ERR_LOG("Check directory failed");
        return E_CHECK_DIR_FAIL;
    }
    if (values.GetObject(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, valueObject)) {
        valueObject.GetString(extension);
    }
    if (values.GetObject(MEDIA_DATA_DB_MEDIA_TYPE, valueObject)) {
        valueObject.GetInt(mediaType);
    }
    if (values.GetObject(MEDIA_DATA_DB_FILE_PATH, valueObject)) {
        valueObject.GetString(path);
    }
    if (extension.compare(MEDIA_NO_FILE) == 0) {
        if (MediaLibraryObjectUtils::IsFileExistInDb(path)) {
            MEDIA_ERR_LOG("dir is existed");
            return E_FILE_EXIST;
        }
        return E_SUCCESS;
    }
    if (!CheckMediaTypeMatchExtension(mediaType, extension)) {
        return E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL;
    }
    extensionVal = dirAsset.GetExtensions();
    mediaTypeVal = dirAsset.GetMediaTypes();
    MEDIA_INFO_LOG("CheckDirInfoUtil extensionVal = %{public}s", extensionVal.c_str());
    MEDIA_INFO_LOG("CheckDirInfoUtil mediaTypeVal = %{public}s", mediaTypeVal.c_str());
    if (!CheckMediaType(mediaTypeVal, mediaType)) {
        return E_CHECK_MEDIATYPE_FAIL;
    }
    if (mediaType == MEDIA_TYPE_FILE) {
        if (!extension.empty() && !CheckFileExtension(dirQuerySetMap, extension)) {
            return E_CHECK_EXTENSION_FAIL;
        }
    } else {
        if (!CheckExtension(extensionVal, extension)) {
            return E_CHECK_EXTENSION_FAIL;
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibraryDirOperations::HandleFMSTrashDir(const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    ValueObject valueObject;
    MediaLibrarySmartAlbumMapOperations smartAlbumMapOprn;
    MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
    SmartAlbumMapQueryData smartAlbumMapQueryData;
    smartAlbumMapQueryData.smartAlbumMapDbOprn = smartAlbumMapDbOprn;
    smartAlbumMapQueryData.values = values;
    smartAlbumMapQueryData.rdbStore = rdbStore;
    smartAlbumMapQueryData.dirQuerySetMap = dirQuerySetMap;
    int32_t dirId = 0;
    if (values.GetObject(MEDIA_DATA_DB_ID, valueObject)) {
        valueObject.GetInt(dirId);
    } else {
        MEDIA_ERR_LOG("HandleFMSTrashDir invalid id");
        return E_FAIL;
    }
    smartAlbumMapQueryData.values.Clear();
    smartAlbumMapQueryData.values.PutInt(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
    smartAlbumMapQueryData.values.PutInt(SMARTALBUMMAP_DB_CHILD_ASSET_ID, dirId);
    return smartAlbumMapOprn.HandleAddAssetOperations(TRASH_ALBUM_ID_VALUES, dirId, smartAlbumMapQueryData);
}

int32_t MediaLibraryDirOperations::GetRootDirAndExtension(string &displayName, string &relativePath,
                                                          int mediaType, ValuesBucket &outValues)
{
    string extension, rootDir;
    int32_t errorCode = E_FAIL;
    if (!MediaFileUtils::CheckDisplayName(displayName)) {
        return E_FILE_NAME_INVALID;
    }
    size_t displayNameIndex = displayName.find(".");
    if ((displayNameIndex == string::npos) && (mediaType != MEDIA_TYPE_FILE)) {
        MEDIA_ERR_LOG("get displayNameIndex failed");
        return E_FILE_NAME_INVALID;
    }
    if (displayNameIndex != string::npos) {
        extension = displayName.substr(displayNameIndex);
        MEDIA_INFO_LOG("extension = %{public}s", extension.c_str());
    }
    size_t dirIndex = relativePath.find("/");
    if (dirIndex != string::npos) {
        rootDir = relativePath.substr(0, dirIndex);
        size_t parentDirIndex = rootDir.find("/");
        if (parentDirIndex == string::npos) {
            rootDir = rootDir + "/";
        }
        MEDIA_INFO_LOG("rootDir = %{public}s", rootDir.c_str());
    } else {
        MEDIA_ERR_LOG("get dirIndex failed");
        errorCode = E_CHECK_ROOT_DIR_FAIL;
        return errorCode;
    }
    outValues.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, extension);
    outValues.PutString(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, rootDir);
    errorCode = E_SUCCESS;
    return errorCode;
}

int32_t MediaLibraryDirOperations::HandleDeleteDir(const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore)
{
    ValueObject valueObject;
    MediaLibraryDirDb dirDbOprn;
    int parent;
    if (values.GetObject(MEDIA_DATA_DB_PARENT_ID, valueObject)) {
        valueObject.GetInt(parent);
    }
    int errorCode = DeleteDirInfoUtil(parent, rdbStore, dirDbOprn);
    return errorCode;
}

int32_t MediaLibraryDirOperations::HandleFMSDeleteDir(const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore)
{
    ValueObject valueObject;
    MediaLibraryDirDb dirDbOprn;
    string relative;
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relative);
    }
    int errorCode = DeleteFMSDirInfoUtil(relative, rdbStore, dirDbOprn);
    return errorCode;
}

static bool HandleSpecialMediaType(const int &mediaType)
{
    if (mediaType == MEDIA_TYPE_NOFILE) {
        MEDIA_DEBUG_LOG("special type %{public}d, pass check", mediaType);
        return true;
    }
    return false;
}

int32_t MediaLibraryDirOperations::HandleCheckDirExtension(const ValuesBucket &values,
                                                           const shared_ptr<RdbStore> &rdbStore,
                                                           const unordered_map<string, DirAsset>
                                                           &dirQuerySetMap)
{
    ValueObject valueObject;
    string displayName, relativePath;
    int mediaType = MEDIA_TYPE_FILE;
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(displayName);
        MEDIA_INFO_LOG("displayName = %{private}s", displayName.c_str());
    }
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
        MEDIA_INFO_LOG("relativePath = %{private}s", relativePath.c_str());
    }
    if (values.GetObject(MEDIA_DATA_DB_MEDIA_TYPE, valueObject)) {
        valueObject.GetInt(mediaType);
        MEDIA_INFO_LOG("mediaType = %{public}d", mediaType);
    }
    if (HandleSpecialMediaType(mediaType)) {
        return E_SUCCESS;
    }
    ValuesBucket GetDirAndExtensionValues;
    int errorCode = GetRootDirAndExtension(displayName, relativePath, mediaType, GetDirAndExtensionValues);
    if (errorCode != E_SUCCESS) {
        MEDIA_ERR_LOG("GetDirAndExtension fail");
        return errorCode;
    }
    string path = ROOT_MEDIA_DIR + relativePath;
    if ((path.substr(path.length() - 1)).compare("/")) {
        path = path.substr(0, path.length() - 1);
    }
    MEDIA_INFO_LOG("path = %{public}s", path.c_str());
    GetDirAndExtensionValues.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    GetDirAndExtensionValues.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    errorCode = CheckDirInfoUtil(GetDirAndExtensionValues, rdbStore, dirQuerySetMap);

    return errorCode;
}

int32_t MediaLibraryDirOperations::HandleDirOperations(const string &oprn,
    const ValuesBucket &valuesBucket, const shared_ptr<RdbStore> &rdbStore,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    int32_t errCode = E_FAIL;
    ValueObject valueObject;
    if (oprn == MEDIA_DIROPRN_DELETEDIR) {
        errCode = HandleDeleteDir(values, rdbStore);
    } else if (oprn == MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION) {
        errCode = HandleCheckDirExtension(values, rdbStore, dirQuerySetMap);
    } else if (oprn == MEDIA_DIROPRN_FMS_CREATEDIR) {
        values.PutString(MEDIA_DATA_DB_NAME, ".nofile");
        values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_TYPE_NOFILE);
        MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
        cmd.SetValueBucket(values);
        errCode = MediaLibraryFileOperations::CreateFileOperation(cmd);
    } else if (oprn == MEDIA_DIROPRN_FMS_DELETEDIR) {
        errCode = HandleFMSDeleteDir(values, rdbStore);
    } else if (oprn == MEDIA_DIROPRN_FMS_TRASHDIR) {
        errCode = HandleFMSTrashDir(values, rdbStore, dirQuerySetMap);
    }
    MEDIA_INFO_LOG("HandleDirOperations erroCode = %{public}d", errCode);
    return errCode;
}
} // namespace Media
} // namespace OHOS
