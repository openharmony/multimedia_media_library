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

#ifndef BACKUP_DATABASE_UTILS_H
#define BACKUP_DATABASE_UTILS_H

#include <string>

#include "backup_const.h"
#include "rdb_helper.h"
#include "result_set.h"

namespace OHOS {
namespace Media {
class BackupDatabaseUtils {
public:
    static int32_t InitDb(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &dbName,
        const std::string &dbPath, const std::string &bundleName, bool isMediaLibary,
            int32_t area = DEFAULT_AREA_VERSION);
    static int32_t QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
        const std::string &column);
    static int32_t Update(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t &changeRows,
        NativeRdb::ValuesBucket &valuesBucket, std::unique_ptr<NativeRdb::AbsRdbPredicates> &predicates);
    static int32_t Delete(NativeRdb::AbsRdbPredicates &predicates, int32_t &changeRows,
        std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static int32_t InitGarbageAlbum(std::shared_ptr<NativeRdb::RdbStore> rdbStore, std::set<std::string> &cacheSet,
        std::unordered_map<std::string, std::string> &nickMap);
    static int32_t QueryGalleryAllCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryImageCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryVideoCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryHiddenCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryTrashedCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryCloneCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGallerySDCardCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryScreenVideoCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryCloudCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryFavoriteCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryImportsCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryExternalImageCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb);
    static int32_t QueryExternalVideoCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb);
    static int32_t QueryExternalAudioCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb);
    static std::shared_ptr<NativeRdb::ResultSet> GetQueryResultSet(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::string &querySql, const std::vector<std::string> &sqlArgs = {});
    static std::unordered_map<std::string, std::string> GetColumnInfoMap(
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName);
    static void UpdateUniqueNumber(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t number,
        const std::string &type);
    static int32_t QueryUniqueNumber(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &type);
    static std::string GarbleInfoName(const std::string &infoName);
    static void UpdateSelection(std::string &selection, const std::string &selectionToAdd, bool needWrap = false);
    static int32_t GetBlob(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> resultSet,
        std::vector<uint8_t> &blobVal);
    static std::string GetLandmarksStr(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    static std::string GetLandmarksStr(const std::vector<uint8_t> &bytes);
    static uint32_t GetUint32ValFromBytes(const std::vector<uint8_t> &bytes, size_t start);
    static void UpdateAnalysisTotalStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static void UpdateAnalysisFaceTagStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static bool GetFaceAnalysisVersion(std::unordered_map<int32_t, std::string> &faceAnalysisVersionMap,
        const std::vector<int32_t> &faceAnalysisTypeList);
    static bool SetTagIdNew(PortraitAlbumInfo &portraitAlbumInfo,
        std::unordered_map<std::string, std::string> &tagIdMap);
    static bool SetVersion(std::string &version, const std::unordered_map<int32_t, std::string> &versionMap,
        int32_t type);
    static bool SetGroupTagNew(PortraitAlbumInfo &portraitAlbumInfo,
        const std::unordered_map<std::string, std::string> &groupTagMap);
    static bool SetLandmarks(FaceInfo &faceInfo, const std::unordered_map<int32_t, FileInfo> &fileInfoMap);
    static bool SetFileIdNew(FaceInfo &faceInfo, const std::unordered_map<int32_t, FileInfo> &fileInfoMap);
    static bool SetTagIdNew(FaceInfo &faceInfo, const std::unordered_map<std::string, std::string> &tagIdMap);
    static bool SetAlbumIdNew(FaceInfo &faceInfo, const std::unordered_map<std::string, int32_t> &albumIdMap);
    static void PrintErrorLog(const std::string &errorLog, int64_t start);

private:
    static std::string CloudSyncTriggerFunc(const std::vector<std::string> &args);
    static std::string IsCallerSelfFunc(const std::vector<std::string> &args);
    static std::string GetVersionByFaceAnalysisType(int32_t type);
};

class RdbCallback : public NativeRdb::RdbOpenCallback {
public:
    virtual int32_t OnCreate(NativeRdb::RdbStore &rdb) override
    {
        return 0;
    }

    virtual int32_t OnUpgrade(NativeRdb::RdbStore &rdb, int32_t oldVersion,
        int32_t newVersion) override
    {
        return 0;
    }
};
} // namespace Media
} // namespace OHOS

#endif  // BACKUP_DATABASE_UTILS_H