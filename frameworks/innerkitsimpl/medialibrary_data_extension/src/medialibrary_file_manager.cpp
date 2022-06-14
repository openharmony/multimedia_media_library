/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "medialibrary_file_manager.h"

#include "media_file_utils.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
MediaLibraryFileManager::MediaLibraryFileManager()
{
    uniStore_ = MediaLibraryUnistoreManager::GetInstance().GetUnistore(MediaLibraryUnistoreType::RDB);
}

int32_t MediaLibraryFileManager::CreateFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    // UNKNOWN_OBJECT mode
    if (uniStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryFileManager Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }
    int64_t outRowId = DATA_ABILITY_FAIL;
    (void)uniStore_->Insert(cmd, outRowId);
    return outRowId;
}

int32_t MediaLibraryFileManager::BatchCreateFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryFileManager::DeleteFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    // string fileId = cmd.GetOprnFileId();
    // if (fileId == "-1") {
    //     MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
    //     return DATA_ABILITY_FAIL;
    // }
    return DeleteInfoInDbWithId(cmd);
}

int32_t MediaLibraryFileManager::RenameFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryFileManager::ModifyFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    // string fileId = cmd.GetOprnFileId();
    // if (fileId == "-1") {
    //     MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
    //     return DATA_ABILITY_FAIL;
    // }
    return ModifyInfoInDbWithId(cmd);
}

std::shared_ptr<DataShare::ResultSetBridge> MediaLibraryFileManager::LookupFile(MediaLibraryCommand &cmd,
                                                                                const std::vector<std::string> &columns)
{
    MEDIA_INFO_LOG("[lqh] enter");
    auto queryResultSet = uniStore_->Query(cmd, columns);
    return RdbUtils::ToResultSetBridge(queryResultSet);
}



int32_t MediaLibraryFileManager::CloseFile(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    MEDIA_ERR_LOG("Not a real file in filesystem, close file failed!");
    return DATA_ABILITY_FAIL;
}

int32_t MediaLibraryFileManager::IsDictionary(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    int32_t id = -1;
    ValueObject valueObject;
    const ValuesBucket values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_ID, valueObject)) {
        valueObject.GetInt(id);
    }
    MEDIA_INFO_LOG("HandleIsDirectoryAsset id = %{private}d", id);
    if (id == -1) {
        MEDIA_ERR_LOG("HandleIsDirectoryAsset: not dictionary id, can't do the judgement!");
        return DATA_ABILITY_FAIL;
    }

    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, std::to_string(id));
    std::vector<std::string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);
    shared_ptr<AbsSharedResultSet> queryResultSet = uniStore_->Query(cmd, columns);
    string path = "";
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndex;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
        queryResultSet->GetString(columnIndex, path);
        MEDIA_INFO_LOG("HandleIsDirectoryAsset path = %{private}s", path.c_str());
    }
    if (MediaFileUtils::IsDirectory(path)) {
        MEDIA_INFO_LOG("HandleIsDirectoryAsset: %{private}s is a dictionary!", path.c_str());
        return DATA_ABILITY_SUCCESS;
    }
    MEDIA_INFO_LOG("HandleIsDirectoryAsset: %{private}s is NOT a dictionary!", path.c_str());
    return DATA_ABILITY_FAIL;
}

int32_t MediaLibraryFileManager::GetCapatity(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    ValueObject valueObject;
    const ValuesBucket values = cmd.GetValueBucket();
    bool isFavourite = false;
    if (values.GetObject(MEDIA_DATA_DB_IS_FAV, valueObject)) {
        valueObject.GetBool(isFavourite);
    }

    bool isTrash = false;
    if (values.GetObject(MEDIA_DATA_DB_IS_TRASH, valueObject)) {
        valueObject.GetBool(isTrash);
    }

    if (isFavourite) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity isFavourite");
        resultSet = QueryFavFiles(cmd);
    } else if (isTrash) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity isTrash");
        resultSet = QueryTrashFiles(cmd);
    }

    if (resultSet != nullptr) {
        MEDIA_INFO_LOG("HandleGetAlbumCapacity not get ");
        return DATA_ABILITY_FAIL;
    }

    int32_t albumCapatity = DATA_ABILITY_FAIL;
    resultSet->GetRowCount(albumCapatity);
    MEDIA_INFO_LOG("HandleGetAlbumCapacity GetRowCount %{private}d", albumCapatity);
    return albumCapatity;
}






shared_ptr<AbsSharedResultSet> MediaLibraryFileManager::QueryFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    vector<string> selectionArgs = {};
    cmd.GetAbsRdbPredicates()->SetWhereArgs(selectionArgs);
    vector<string> columns;

    shared_ptr<AbsSharedResultSet> resultSet = uniStore_->Query(cmd, columns);

    return resultSet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileManager::QueryFavFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strQueryCondition = MEDIA_DATA_DB_IS_FAV + " = 1 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> 8";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    return QueryFiles(cmd);
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileManager::QueryTrashFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strQueryCondition = MEDIA_DATA_DB_DATE_TRASHED + " > 0 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> 8";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    return QueryFiles(cmd);
}




} // namespace Media
} // namespace OHOS
