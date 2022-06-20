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

#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_object_utils.h"
#include "values_bucket.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

MediaLibraryAlbumOperations::MediaLibraryAlbumOperations()
{
    uniStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
}

int32_t MediaLibraryAlbumOperations::HandleAlbumOperations(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnType()) {
    case CREATE:
        return CreateAlbumOperation(cmd); break;
    case DELETE:
        return DeleteAlbumOperation(cmd); break;
    case UPDATE:
        return ModifyAlbumOperation(cmd); break;
    default:
        return DATA_ABILITY_SUCCESS;
    }
    return DATA_ABILITY_SUCCESS;
}


int32_t MediaLibraryAlbumOperations::CreateAlbumOperation(MediaLibraryCommand &cmd)
{
    int64_t outRow = -1;
    MediaLibraryObjectUtils objUtils;
    int32_t errCode = objUtils.CreateDirObj(cmd, outRow);
    if (errCode == DATA_ABILITY_SUCCESS) {
        return outRow;
    }
    return errCode;
}

int32_t MediaLibraryAlbumOperations::DeleteAlbumOperation(MediaLibraryCommand &cmd)
{
    string strId = cmd.GetOprnFileId();
    MediaLibraryObjectUtils objUtils;
    string dirPath = objUtils.GetPathByIdFromDb(strId);
    if (dirPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strId.c_str());
        return DATA_ABILITY_FAIL;
    }
    return objUtils.DeleteDirObj(cmd, dirPath);
}

// only support modify in the same parent folder, like: a/b/c --> a/b/d
int32_t MediaLibraryAlbumOperations::ModifyAlbumOperation(MediaLibraryCommand &cmd)
{
    string strId = cmd.GetOprnFileId();
    MediaLibraryObjectUtils objUtils;
    string srcDirPath = objUtils.GetPathByIdFromDb(strId);
    if (srcDirPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strId.c_str());
        return DATA_ABILITY_FAIL;
    }

    ValuesBucket values = const_cast<ValuesBucket &>(cmd.GetValueBucket());
    string dstDirName = "";
    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_ALBUM_NAME, valueObject)) {
        valueObject.GetString(dstDirName);
    }
    string dstDirPath = MediaLibraryDataManagerUtils::GetParentPath(srcDirPath) + "/" + dstDirName;

    return objUtils.RenameDirObj(cmd, srcDirPath, dstDirPath);
}

string MediaLibraryAlbumOperations::GetDistributedAlbumSql(const string &strQueryCondition, const string &tableName)
{
    string distributedAlbumSql;
    if (!strQueryCondition.empty()) {
        distributedAlbumSql = "SELECT * FROM ( " + DISTRIBUTED_ABLUM_COLUMNS + " FROM " +
        tableName + " " + FILE_TABLE + ", " + tableName + " " + ABLUM_TABLE +
        DISTRIBUTED_ABLUM_WHERE_AND_GROUPBY + " )" +
        " WHERE " + strQueryCondition;
    } else {
        distributedAlbumSql = "SELECT * FROM ( " + DISTRIBUTED_ABLUM_COLUMNS + " FROM " +
        tableName + " " + FILE_TABLE + ", " + tableName + " " + ABLUM_TABLE +
        DISTRIBUTED_ABLUM_WHERE_AND_GROUPBY + " )";
    }
    MEDIA_INFO_LOG("GetDistributedAlbumSql distributedAlbumSql = %{private}s", distributedAlbumSql.c_str());
    return distributedAlbumSql;
}

shared_ptr<AbsSharedResultSet> MediaLibraryAlbumOperations::QueryAlbumOperation(
    MediaLibraryCommand &cmd, vector<string> columns)
{
    if (uniStore_ == nullptr) {
        MEDIA_WARNING_LOG("uniStore is nullptr");
        return nullptr;
    }

    if (cmd.GetOprnObject() == OperationObject::MEDIA_VOLUME) {
        MEDIA_DEBUG_LOG("QUERY_MEDIA_VOLUME = %{public}s", QUERY_MEDIA_VOLUME.c_str());
        return uniStore_->QuerySql(QUERY_MEDIA_VOLUME);
    }

    string strQueryCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    string networkId = cmd.GetOprnDevice();
    if (!networkId.empty()) {
        string tableName = uniStore_->ObtainTableName(cmd);
        MEDIA_INFO_LOG("tableName is %{private}s", tableName.c_str());
        if (!strQueryCondition.empty()) {
            strQueryCondition = MediaLibraryDataManagerUtils::ObtionCondition(strQueryCondition,
                cmd.GetAbsRdbPredicates()->GetWhereArgs());
        }
        string distributedAlbumSql = GetDistributedAlbumSql(strQueryCondition, tableName);
        return uniStore_->QuerySql(distributedAlbumSql);
    }

    if (!strQueryCondition.empty()) {
        return uniStore_->Query(cmd, columns);
    }
    string querySql = "SELECT * FROM " + cmd.GetTableName();
    return uniStore_->QuerySql(querySql);
}

} // namespace Media
} // namespace OHOS
