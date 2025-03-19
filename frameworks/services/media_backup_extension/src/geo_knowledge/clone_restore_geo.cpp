/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "clone_restore_geo.h"

#include "backup_database_utils.h"
#include "medialibrary_data_manager_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "locale_config.h"
#include "upgrade_restore_task_report.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS::Media {
const int32_t PAGE_SIZE = 200;
const int32_t UPDATE_GEO = 3;
const string NOT_MATCH = "NOT MATCH";
const string LATITUDE = "latitude";
const string LONGITUDE = "longitude";
const string LOCATION_KEY = "location_key";
const string CITY_ID = "city_id";
const string LANGUAGE = "language";
const string COUNTRY = "country";
const string ADMIN_AREA = "admin_area";
const string SUB_ADMIN_AREA = "sub_admin_area";
const string LOCALITY = "locality";
const string SUB_LOCALITY = "sub_locality";
const string THOROUGHFARE = "thoroughfare";
const string SUB_THOROUGHFARE = "sub_thoroughfare";
const string FEATURE_NAME = "feature_name";
const string CITY_NAME = "city_name";
const string ADDRESS_DESCRIPTION = "address_description";
const string AOI = "aoi";
const string POI = "poi";
const string FIRST_AOI = "first_aoi";
const string FIRST_POI = "first_poi";
const string LOCATION_VERSION = "location_version";
const string FIRST_AOI_CATEGORY = "first_aoi_category";
const string FIRST_POI_CATEGORY = "first_poi_category";
const string LOCATION_TYPE = "location_type";
const string FILE_ID = "file_id";
const string DATA = "data";
const string SINGLE_CH = "zh-Hans";
const string GEO = "geo";
const string GEO_KNOWLEDGE_TABLE = "tab_analysis_geo_knowledge";
const string ANA_TOTAL_TABLE = "tab_analysis_total";
const string INTEGER = "INTEGER";
const int32_t GEO_STATUS_SUCCESS = 1;
const int32_t ANALYSISED_STATUS = 2;
constexpr double DOUBLE_EPSILON = 1e-15;

const unordered_map<string, unordered_set<string>> COMPARED_COLUMNS_MAP = {
    { "tab_analysis_geo_knowledge",
        {
            "latitude",
            "longitude",
            "location_key",
            "city_id",
            "language",
            "country",
            "admin_area",
            "sub_admin_area",
            "locality",
            "sub_locality",
            "thoroughfare",
            "sub_thoroughfare",
            "feature_name",
            "city_name",
            "address_description",
            "aoi",
            "poi",
            "first_aoi",
            "first_poi",
            "location_version",
            "first_aoi_category",
            "first_poi_category",
            "file_id",
            "location_type"
        }
    }
};

template<typename Key, typename Value>
Value GetValueFromMap(const unordered_map<Key, Value> &map, const Key &key, const Value &defaultValue = Value())
{
    auto it = map.find(key);
    CHECK_AND_RETURN_RET(it != map.end(), defaultValue);
    return it->second;
}

void CloneRestoreGeo::Init(int32_t sceneCode, const std::string &taskId,
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> mediaRdb)
{
    sceneCode_ = sceneCode;
    taskId_ = taskId;
    mediaLibraryRdb_ = mediaLibraryRdb;
    mediaRdb_ = mediaRdb;
    successInsertCnt_ = 0;
    successUpdateCnt_ = 0;
    failInsertCnt_ = 0;
    failUpdateCnt_ = 0;
    systemLanguage_ = Global::I18n::LocaleConfig::GetSystemLanguage();
}

void CloneRestoreGeo::RestoreGeoKnowledgeInfos()
{
    bool cond = (mediaRdb_ == nullptr || mediaLibraryRdb_ == nullptr);
    CHECK_AND_RETURN_LOG(!cond, "rdbStore is nullptr");
    GetGeoKnowledgeInfos();
    GetAnalysisGeoInfos();
}

void CloneRestoreGeo::GetGeoKnowledgeInfos()
{
    std::unordered_map<std::string, std::string> columns;
    columns[FILE_ID] = INTEGER;
    bool hasRequiredColumns = CheckTableColumns(GEO_KNOWLEDGE_TABLE, columns);
    if (!hasRequiredColumns) {
        MEDIA_ERR_LOG("The tab_analysis_geo_knowledge does not contain the required columns.");
        ErrorInfo errorInfo(RestoreError::TABLE_LACK_OF_COLUMN, static_cast<int32_t>(columns.size()),
            "", "The tab_analysis_geo_knowledge does not contain file_id");
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return;
    }
    const std::string QUERY_SQL_GEO = "SELECT * FROM " + GEO_KNOWLEDGE_TABLE + " WHERE " + FILE_ID +
        " in (SELECT " + FILE_ID + " FROM Photos) LIMIT ?, ?";
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, PAGE_SIZE};
        auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, QUERY_SQL_GEO, params);
        CHECK_AND_BREAK_ERR_LOG(resultSet != nullptr, "Query resultSql is null.");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            GeoCloneInfo info;
            GetGeoKnowledgeInfo(info, resultSet);
            geoInfos_.emplace_back(info);
        }

        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount > 0);
    MEDIA_INFO_LOG("query tab_analysis_geo_knowledge nums: %{public}zu", geoInfos_.size());
}

void CloneRestoreGeo::GetAnalysisGeoInfos()
{
    std::unordered_map<std::string, std::string> columns;
    columns[FILE_ID] = INTEGER;
    columns[GEO] = INTEGER;
    bool hasRequiredColumns = CheckTableColumns(ANA_TOTAL_TABLE, columns);
    if (!hasRequiredColumns) {
        MEDIA_ERR_LOG("The tab_analysis_total does not contain the required columns.");
        ErrorInfo errorInfo(RestoreError::TABLE_LACK_OF_COLUMN, static_cast<int32_t>(columns.size()),
            "", "The tab_analysis_total does not contain file_id or geo");
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return;
    }
    const std::string QUERY_SQL_ANA = "SELECT " + FILE_ID + ", " + GEO + " FROM " + ANA_TOTAL_TABLE +
        " WHERE " + FILE_ID + " in (SELECT " + FILE_ID + " FROM Photos) LIMIT ?, ?";
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, PAGE_SIZE};
        auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, QUERY_SQL_ANA, params);
        CHECK_AND_BREAK_ERR_LOG(resultSet != nullptr, "Query resultSql is null.");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            AnaTotalInfo info;
            info.fileId = GetInt32Val(FILE_ID, resultSet);
            info.geo = GetInt32Val(GEO, resultSet);
            anaTotalfos_.emplace_back(info);
        }

        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount > 0);
    MEDIA_INFO_LOG("query tab_analysis_total nums: %{public}zu", anaTotalfos_.size());
}

bool CloneRestoreGeo::CheckTableColumns(const std::string& tableName,
    std::unordered_map<std::string, std::string>& columns)
{
    std::unordered_map<std::string, std::string> srcColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
    std::unordered_set<std::string> result;
    for (auto it = columns.begin(); it != columns.end(); ++it) {
        if (srcColumnInfoMap.find(it->first) != srcColumnInfoMap.end()) {
            result.insert(it->first);
            continue;
        }
        return false;
    }
    return true;
}

void CloneRestoreGeo::GetGeoKnowledgeInfo(GeoCloneInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    info.locationKey = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, LOCATION_KEY);
    info.cityId = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, CITY_ID);
    info.language = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, LANGUAGE);
    info.country = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, COUNTRY);
    info.adminArea = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ADMIN_AREA);
    info.subAdminArea = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SUB_ADMIN_AREA);
    info.locality = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, LOCALITY);
    info.subLocality = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SUB_LOCALITY);
    info.thoroughfare = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, THOROUGHFARE);
    info.subThoroughfare = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SUB_THOROUGHFARE);
    info.featureName = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FEATURE_NAME);
    info.cityName = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, CITY_NAME);
    info.addressDescription = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ADDRESS_DESCRIPTION);
    info.aoi = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, AOI);
    info.poi = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, POI);
    info.firstAoi = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FIRST_AOI);
    info.firstPoi = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FIRST_POI);
    info.locationVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, LOCATION_VERSION);
    info.firstAoiCategory = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FIRST_AOI_CATEGORY);
    info.firstPoiCategory = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FIRST_POI_CATEGORY);
    info.locationType = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, LOCATION_TYPE);
    info.latitude = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, LATITUDE);
    info.longitude = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, LONGITUDE);
}

void CloneRestoreGeo::RestoreMaps(std::vector<FileInfo> &fileInfos)
{
    MEDIA_INFO_LOG("CloneRestoreGeo RestoreMaps");
    bool cond = (mediaRdb_ == nullptr || mediaLibraryRdb_ == nullptr);
    CHECK_AND_RETURN_LOG(!cond, "rdbStore is nullptr");
    CHECK_AND_RETURN_INFO_LOG(!geoInfos_.empty(), "geoInfos_ is empty");
    int32_t batchCnt = 0;
    int32_t batchAnaCnt = 0;
    std::vector<std::string> fileIds;
    std::vector<NativeRdb::ValuesBucket> values;
    std::vector<std::string> analysisIds;
    BatchQueryPhoto(fileInfos);
    for (const auto &fileInfo : fileInfos) {
        std::string fileIdString = UpdateMapInsertValues(values, analysisIds, fileInfo, batchCnt, batchAnaCnt);
        CHECK_AND_EXECUTE(fileIdString == NOT_MATCH, fileIds.emplace_back(fileIdString));
    }
    int64_t rowNum = 0;
    int32_t errCodeGeo = BatchInsertWithRetry(GEO_KNOWLEDGE_TABLE, values, rowNum);
    if (errCodeGeo != E_OK) {
        MEDIA_ERR_LOG("GeoKnowledge: RestoreMaps insert fail");
        ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(values.size()),
            "errCodeGeo: " + std::to_string(errCodeGeo), "GeoKnowledge: RestoreMaps insert fail");
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        failInsertCnt_ += batchCnt;
        return;
    }
    successInsertCnt_ += batchCnt;
    int32_t errCodeUpdate = BatchUpdate(ANA_TOTAL_TABLE, fileIds);
    if (errCodeUpdate != E_OK) {
        FailUpdate(errCodeUpdate, batchCnt, batchAnaCnt);
        return;
    }
    int32_t errCodeUpdateAna = BatchUpdateAna(ANA_TOTAL_TABLE, analysisIds);
    if (errCodeUpdateAna != E_OK) {
        FailUpdateAna(errCodeUpdateAna, batchAnaCnt);
        return;
    }
    successUpdateCnt_ += batchCnt;
}

void CloneRestoreGeo::BatchQueryPhoto(std::vector<FileInfo> &fileInfos)
{
    std::stringstream querySql;
    querySql << "SELECT " + FILE_ID + ", " + DATA + " FROM Photos WHERE " + DATA + " IN (";
    std::vector<NativeRdb::ValueObject> params;
    int32_t count = 0;
    for (const auto &fileInfo : fileInfos) {
        // no need query or alreay queried
        bool cond = ((fabs(fileInfo.latitude) < DOUBLE_EPSILON && fabs(fileInfo.longitude) < DOUBLE_EPSILON)
            || fileInfo.fileIdNew > 0);
        CHECK_AND_CONTINUE(!cond);
        querySql << (count++ > 0 ? "," : "");
        querySql << "?";
        params.emplace_back(fileInfo.cloudPath);
    }
    querySql << ")";
    auto resultSet = BackupDatabaseUtils::QuerySql(mediaLibraryRdb_, querySql.str(), params);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "resultSet is nullptr");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId = GetInt32Val(FILE_ID, resultSet);
        std::string data = GetStringVal(DATA, resultSet);
        auto it = std::find_if(fileInfos.begin(), fileInfos.end(),
            [data](const FileInfo& info) {
                return info.cloudPath == data;
            });
        CHECK_AND_CONTINUE(it != fileInfos.end());
        it->fileIdNew = fileId;
    }
    resultSet->Close();
}

std::string CloneRestoreGeo::UpdateMapInsertValues(std::vector<NativeRdb::ValuesBucket> &values,
    std::vector<std::string> &analysisIds, const FileInfo &fileInfo, int32_t &batchCnt, int32_t &batchAnaCnt)
{
    // no need restore or info missing
    bool cond = ((fabs(fileInfo.latitude) < DOUBLE_EPSILON && fabs(fileInfo.longitude) < DOUBLE_EPSILON)
        || fileInfo.fileIdNew <= 0);
    CHECK_AND_RETURN_RET(!cond, NOT_MATCH);
    return UpdateByGeoLocation(values, analysisIds, fileInfo, batchCnt, batchAnaCnt);
}

std::string CloneRestoreGeo::UpdateByGeoLocation(std::vector<NativeRdb::ValuesBucket> &values,
    std::vector<std::string> &analysisIds, const FileInfo &fileInfo, int32_t &batchCnt, int32_t &batchAnaCnt)
{
    std::string language = systemLanguage_;
    double latitude = fileInfo.latitude;
    double longitude = fileInfo.longitude;
    int32_t fileIdOld = fileInfo.fileIdOld;
    CHECK_AND_EXECUTE(!language.empty(), language = SINGLE_CH);
    auto itGeo = std::find_if(geoInfos_.begin(), geoInfos_.end(),
        [latitude, longitude, language](const GeoCloneInfo& info) {
            bool cond = (!info.latitude.has_value() || !info.longitude.has_value() || !info.language.has_value());
            CHECK_AND_RETURN_RET(!cond, false);
            return fabs(info.latitude.value() - latitude) < 0.0001
                && fabs(info.longitude.value() - longitude) < 0.0001 && info.language.value() == language;
        });
    if (itGeo == geoInfos_.end()) {
        MEDIA_INFO_LOG("not match fileId: %{public}d", fileInfo.fileIdNew);
        return NOT_MATCH;
    }

    std::unordered_set<std::string> intersection = GetCommonColumns(GEO_KNOWLEDGE_TABLE);
    NativeRdb::ValuesBucket value;
    GetMapInsertValue(value, itGeo, intersection, fileInfo.fileIdNew);
    values.emplace_back(value);
    batchCnt++;
    auto comparedColumns = GetValueFromMap(COMPARED_COLUMNS_MAP, GEO_KNOWLEDGE_TABLE);
    if (intersection.size() == comparedColumns.size()) {
        auto itAna = std::find_if(anaTotalfos_.begin(), anaTotalfos_.end(),
            [fileIdOld](const AnaTotalInfo& info) {
            return info.fileId == fileIdOld && info.geo == ANALYSISED_STATUS;
        });
        if (itAna != anaTotalfos_.end()) {
            analysisIds.emplace_back(std::to_string(fileInfo.fileIdNew));
            batchAnaCnt++;
            return NOT_MATCH;
        }
    }
    return std::to_string(fileInfo.fileIdNew);
}

std::unordered_set<std::string> CloneRestoreGeo::GetCommonColumns(const string &tableName)
{
    std::unordered_map<std::string, std::string> srcColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
    std::unordered_map<std::string, std::string> dstColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_, tableName);
    std::unordered_set<std::string> result;
    auto comparedColumns = GetValueFromMap(COMPARED_COLUMNS_MAP, tableName);
    for (auto it = dstColumnInfoMap.begin(); it != dstColumnInfoMap.end(); ++it) {
        bool cond = (srcColumnInfoMap.find(it->first) != srcColumnInfoMap.end() &&
            comparedColumns.count(it->first) > 0);
        CHECK_AND_EXECUTE(!cond, result.insert(it->first));
    }
    return result;
}

void CloneRestoreGeo::GetMapInsertValue(NativeRdb::ValuesBucket &value, std::vector<GeoCloneInfo>::iterator it,
    const std::unordered_set<std::string> &intersection, int32_t fileId)
{
    value.PutInt(FILE_ID, fileId);
    PutIfInIntersection(value, LOCATION_KEY, it->locationKey, intersection);
    PutIfInIntersection(value, CITY_ID, it->cityId, intersection);
    PutIfInIntersection(value, LANGUAGE, it->language, intersection);
    PutIfInIntersection(value, COUNTRY, it->country, intersection);
    PutIfInIntersection(value, ADMIN_AREA, it->adminArea, intersection);
    PutIfInIntersection(value, SUB_ADMIN_AREA, it->subAdminArea, intersection);
    PutIfInIntersection(value, LOCALITY, it->locality, intersection);
    PutIfInIntersection(value, SUB_LOCALITY, it->subLocality, intersection);
    PutIfInIntersection(value, THOROUGHFARE, it->thoroughfare, intersection);
    PutIfInIntersection(value, SUB_THOROUGHFARE, it->subThoroughfare, intersection);
    PutIfInIntersection(value, FEATURE_NAME, it->featureName, intersection);
    PutIfInIntersection(value, CITY_NAME, it->cityName, intersection);
    PutIfInIntersection(value, ADDRESS_DESCRIPTION, it->addressDescription, intersection);
    PutIfInIntersection(value, AOI, it->aoi, intersection);
    PutIfInIntersection(value, POI, it->poi, intersection);
    PutIfInIntersection(value, FIRST_AOI, it->firstAoi, intersection);
    PutIfInIntersection(value, FIRST_POI, it->firstPoi, intersection);
    PutIfInIntersection(value, LOCATION_VERSION, it->locationVersion, intersection);
    PutIfInIntersection(value, FIRST_AOI_CATEGORY, it->firstAoiCategory, intersection);
    PutIfInIntersection(value, FIRST_POI_CATEGORY, it->firstPoiCategory, intersection);
    PutIfInIntersection(value, LOCATION_TYPE, it->locationType, intersection);
    PutIfInIntersection(value, LATITUDE, it->latitude, intersection);
    PutIfInIntersection(value, LONGITUDE, it->longitude, intersection);
}

int32_t CloneRestoreGeo::BatchInsertWithRetry(const std::string &tableName,
    std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum)
{
    CHECK_AND_RETURN_RET(!values.empty(), E_OK);
    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(mediaLibraryRdb_);
    std::function<int(void)> func = [&]()->int {
        errCode = trans.BatchInsert(rowNum, tableName, values);
        CHECK_AND_PRINT_LOG(errCode == E_OK, "InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.",
            errCode, (long)rowNum);
        return errCode;
    };

    errCode = trans.RetryTrans(func, true);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "BatchInsertWithRetry: tans finish fail!, ret:%{public}d", errCode);
    return errCode;
}

int32_t CloneRestoreGeo::BatchUpdate(const std::string &tableName, std::vector<std::string> &fileIds)
{
    std::unique_ptr<NativeRdb::AbsRdbPredicates> updatePredicates =
        make_unique<NativeRdb::AbsRdbPredicates>(tableName);
    updatePredicates->In(FILE_ID, fileIds);
    NativeRdb::ValuesBucket rdbValues;
    rdbValues.PutInt(GEO, UPDATE_GEO);
    int32_t changedRows = -1;
    int32_t errCode = E_OK;

    errCode = BackupDatabaseUtils::Update(mediaLibraryRdb_, changedRows, rdbValues, updatePredicates);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "Database update failed, errCode = %{public}d", errCode);
    return errCode;
}

int32_t CloneRestoreGeo::BatchUpdateAna(const std::string &tableName, std::vector<std::string> &analysisIds)
{
    std::unique_ptr<NativeRdb::AbsRdbPredicates> updatePredicates =
        make_unique<NativeRdb::AbsRdbPredicates>(tableName);
    updatePredicates->In(FILE_ID, analysisIds);
    NativeRdb::ValuesBucket rdbValues;
    rdbValues.PutInt(GEO, ANALYSISED_STATUS);
    int32_t changedRows = -1;
    int32_t errCode = E_OK;
    errCode = BackupDatabaseUtils::Update(mediaLibraryRdb_, changedRows, rdbValues, updatePredicates);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "Database update failed, errCode = %{public}d", errCode);
    return errCode;
}

void CloneRestoreGeo::FailUpdate(int32_t errCodeUpdate, int32_t &batchCnt, int32_t &batchAnaCnt)
{
    batchCnt -= batchAnaCnt;
    failUpdateCnt_ += batchCnt;
    MEDIA_ERR_LOG("AnalysisTotal: RestoreMaps update fail");
    ErrorInfo errorInfo(RestoreError::UPDATE_FAILED, batchCnt,
        "errCodeUpdate: " + std::to_string(errCodeUpdate), "AnalysisTotal: RestoreMaps update fail");
    UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
}

void CloneRestoreGeo::FailUpdateAna(int32_t errCodeUpdateAna, int32_t &batchAnaCnt)
{
    failUpdateCnt_ += batchAnaCnt;
    MEDIA_ERR_LOG("AnalysisTotal: RestoreMaps updateAna fail");
    ErrorInfo errorInfo(RestoreError::UPDATE_FAILED, batchAnaCnt,
        "errCodeUpdateAna: " + std::to_string(errCodeUpdateAna), "AnalysisTotal: RestoreMaps updateAna fail");
    UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
}

void CloneRestoreGeo::ReportGeoRestoreTask()
{
    MEDIA_INFO_LOG("GeoKnowledge Insert successInsertCnt_: %{public}d, failInsertCnt_: %{public}d, "
        "AnalysisTotal Update successUpdateCnt_: %{public}d, failUpdateCnt_: %{public}d, "
        "Current System Language: %{public}s",
        successInsertCnt_.load(), failInsertCnt_.load(), successUpdateCnt_.load(),
        failUpdateCnt_.load(), systemLanguage_.c_str());
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_)
        .Report("GeoKnowledge Restore", std::to_string(GEO_STATUS_SUCCESS),
        "successInsertCnt_: " + std::to_string(successInsertCnt_) +
        ", failInsertCnt_: " + std::to_string(failInsertCnt_) +
        ", successUpdateCnt_: " + std::to_string(successUpdateCnt_) +
        ", failUpdateCnt_: " + std::to_string(failUpdateCnt_) +
        ", Current System Language: " + systemLanguage_);
}
} // namespace OHOS::Media