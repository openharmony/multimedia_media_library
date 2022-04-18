/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "medialibrary_album_operations.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t InsertAlbumInfoUtil(const ValuesBucket &valuesBucket,
                            const string &albumPath,
                            shared_ptr<RdbStore> rdbStore,
                            const MediaLibraryAlbumDb &albumDbOprn,
                            vector<int32_t> &outIds)
{
    string albumName, title;
    NativeAlbumAsset albumAsset = MediaLibraryDataManagerUtils::GetLastAlbumExistInDb(albumPath, rdbStore);
    string parentPath = albumAsset.GetAlbumPath();
    int32_t parentId = albumAsset.GetAlbumId();
    string path = albumPath;
    while (parentPath.length() < path.length() - 1) {
        ValuesBucket values;
        string relativePath;
        if (path.substr(path.length() - 1) != "/") {
            path = path + "/";
        }
        size_t index = path.find("/", parentPath.length() + 1);
        parentPath = path.substr(0, index);
        values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, parentPath);
        title = parentPath;
        size_t titleIndex = parentPath.rfind('/');
        if (index != string::npos) {
            title = parentPath.substr(titleIndex + 1);
            relativePath = parentPath.substr(0, titleIndex);
            if (relativePath.length() > ROOT_MEDIA_DIR.length()) {
                relativePath = relativePath.substr(ROOT_MEDIA_DIR.length()) + "/";
            } else {
                relativePath = "";
            }
        }
        if (!MediaLibraryDataManagerUtils::CheckDisplayName(title)) {
            parentId = DATA_ABILITY_VIOLATION_PARAMETERS;
            MediaLibraryDataManagerUtils::DeleteDirectorys(outIds, rdbStore);
            break;
        }
        values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
        values.PutString(Media::MEDIA_DATA_DB_TITLE, title);
        values.PutString(Media::MEDIA_DATA_DB_NAME, title);
        values.PutInt(Media::MEDIA_DATA_DB_MEDIA_TYPE, MediaType::MEDIA_TYPE_ALBUM);
        values.PutInt(Media::MEDIA_DATA_DB_PARENT_ID, parentId);
        values.PutLong(MEDIA_DATA_DB_DATE_ADDED,
                       MediaLibraryDataManagerUtils::GetAlbumDateModified(path));
        values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED,
                       MediaLibraryDataManagerUtils::GetAlbumDateModified(path));
        parentId = const_cast<MediaLibraryAlbumDb &>(albumDbOprn).InsertAlbumInfo(values, rdbStore);
        outIds.push_back(parentId);
        if (index == string::npos) {
            albumName = parentPath;
            break;
        }
    }
    return parentId;
}
int32_t UpdateAlbumInfoUtil(const ValuesBucket &valuesBucket,
                            const string &albumPath,
                            const string &albumNewName,
                            shared_ptr<RdbStore> rdbStore,
                            const MediaLibraryAlbumDb &albumDbOprn)
{
    int32_t retVal = DATA_ABILITY_FAIL;
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    string newAlbumPath;

    if ((rdbStore == nullptr) || (albumPath.empty()) || (albumNewName.empty())) {
        return retVal;
    }

    if (albumNewName.at(0) == '.') {
        int32_t deletedRows = ALBUM_OPERATION_ERR;
        vector<string> whereArgs = {(albumPath.back() != '/' ? (albumPath + "/%") : (albumPath + "%")),
        albumPath};

    int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE,
    MEDIA_DATA_DB_FILE_PATH + " LIKE ? OR " + MEDIA_DATA_DB_FILE_PATH + " = ?", whereArgs);
        if (deleteResult != E_OK) {
            MEDIA_ERR_LOG("Delete rows failed");
        }
        return DATA_ABILITY_SUCCESS;
    }

    size_t slashIndex = albumPath.rfind("/");
    if (slashIndex != string::npos) {
        newAlbumPath = albumPath.substr(0, slashIndex) + "/" + albumNewName;
        values.PutString(Media::MEDIA_DATA_DB_RELATIVE_PATH, albumPath.substr(0, slashIndex));
    }

    values.PutString(Media::MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED,
                   MediaLibraryDataManagerUtils::GetAlbumDateModified(newAlbumPath));

    retVal = const_cast<MediaLibraryAlbumDb &>(albumDbOprn).UpdateAlbumInfo(values, rdbStore);
    if ((retVal == DATA_ABILITY_SUCCESS) && (!newAlbumPath.empty())) {
        // Update the path, relative path and album Name for internal files
        const std::string modifyAlbumInternalsStmt =
    "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_FILE_PATH + " = replace("
    + MEDIA_DATA_DB_FILE_PATH + ", '" + albumPath + "/' , '" + newAlbumPath + "/'), "
    + MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
    + ", '" + albumPath + "', '" + newAlbumPath + "'), "
    + MEDIA_DATA_DB_ALBUM_NAME + " = replace(" + MEDIA_DATA_DB_ALBUM_NAME + ", '"
    + albumPath.substr(slashIndex + 1) + "', '" + albumNewName + "')"
    + "where " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + albumPath + "/%'";

        auto ret = rdbStore->ExecuteSql(modifyAlbumInternalsStmt);
        CHECK_AND_PRINT_LOG(ret == 0, "Album update sql failed");
    }

    return retVal;
}

int32_t DeleteAlbumInfoUtil(const ValuesBucket &valuesBucket, int32_t albumId, const string &albumPath,
                            shared_ptr<RdbStore> rdbStore, const MediaLibraryAlbumDb &albumDbOprn)
{
    int32_t retVal;
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);

    retVal = const_cast<MediaLibraryAlbumDb &>(albumDbOprn).DeleteAlbumInfo(albumId, rdbStore);
    if ((retVal == DATA_ABILITY_SUCCESS) && (rdbStore != nullptr) && (!albumPath.empty())) {
        int32_t deletedRows = ALBUM_OPERATION_ERR;
        vector<string> whereArgs = {(albumPath.back() != '/' ? (albumPath + "/%") : (albumPath + "%"))};

    int32_t deleteResult = rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE,
    MEDIA_DATA_DB_FILE_PATH + " LIKE ?", whereArgs);
        if (deleteResult != E_OK) {
            MEDIA_ERR_LOG("Delete rows failed");
        }
    }

    return retVal;
}

int32_t MediaLibraryAlbumOperations::HandleAlbumOperations(const string &oprn,
                                                           const ValuesBucket &valuesBucket,
                                                           const shared_ptr<RdbStore> &rdbStore,
                                                           vector<int32_t> &outIds)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    AlbumAsset albumAsset;
    MediaLibraryAlbumDb albumDbOprn;
    int32_t errCode = DATA_ABILITY_FAIL;
    ValueObject valueObject;
    int32_t outRow = -1;
    if (oprn == MEDIA_ALBUMOPRN_CREATEALBUM) {
        string albumPath = "";
        if (values.GetObject(MEDIA_DATA_DB_FILE_PATH, valueObject)) {
            valueObject.GetString(albumPath);
        }
        CHECK_AND_RETURN_RET_LOG(!albumPath.empty(), DATA_ABILITY_FAIL, "Path is empty");
        albumAsset.SetAlbumPath(albumPath);
        if (!MediaLibraryDataManagerUtils::isAlbumExistInDb(albumPath, rdbStore, outRow)) {
            albumAsset.CreateAlbumAsset();
            errCode = InsertAlbumInfoUtil(values, albumPath, rdbStore, albumDbOprn, outIds);
        } else {
            if (!MediaFileUtils::IsDirectory(albumPath)) {
                albumAsset.CreateAlbumAsset();
            } else {
                outRow = DATA_ABILITY_DUPLICATE_CREATE;
            }
            return outRow;
        }
    } else {
        int32_t albumId = 0;
        if (values.GetObject(MEDIA_DATA_DB_ID, valueObject)) {
            valueObject.GetInt(albumId);
        }
        string albumPath = MediaLibraryDataManagerUtils::GetPathFromDb(to_string(albumId), rdbStore);
        if (albumPath.empty()) {
            return errCode;
        }
        if (oprn == MEDIA_ALBUMOPRN_MODIFYALBUM) {
            string albumNewName = "";
    if (values.GetObject(MEDIA_DATA_DB_ALBUM_NAME, valueObject)) {
                valueObject.GetString(albumNewName);
            }
            albumAsset.SetAlbumName(albumNewName);
            if (albumAsset.ModifyAlbumAsset(albumPath) == true) {
                errCode = UpdateAlbumInfoUtil(values, albumPath, albumNewName, rdbStore, albumDbOprn);
            }
        } else if (oprn == MEDIA_ALBUMOPRN_DELETEALBUM) {
            if (albumAsset.DeleteAlbumAsset(albumPath) == true) {
                errCode = DeleteAlbumInfoUtil(values, albumId, albumPath, rdbStore, albumDbOprn);
            }
        }
    }

    return errCode;
}
int32_t MediaLibraryAlbumOperations::HandleAlbumOperations(const string &oprn,
                                                           const ValuesBucket &valuesBucket,
                                                           const shared_ptr<RdbStore> &rdbStore)
{
    vector<int32_t> outIds;
    return HandleAlbumOperations(oprn, valuesBucket, rdbStore, outIds);
}
} // namespace Media
} // namespace OHOS