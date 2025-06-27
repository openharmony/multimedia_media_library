/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_trigger.h"
#include "photo_album_column.h"
#include "media_log.h"
#include "media_column.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "medialibrary_notify.h"
#include "medialibrary_trigger_utils.h"
#include "album_accurate_refresh.h"
#include "asset_accurate_refresh.h"

namespace OHOS {
namespace Media {

static constexpr int32_t ALBUM_PRIORITY_DEFAULT = 1;

static std::string GetPackageNameAndOwnerPackageKey(
    const std::string& packageName, const std::string& ownerPackage)
{
    return packageName + "#" + ownerPackage;
}

void TriggerHelper::AddFocusedColumnName(const std::unordered_set<std::string>& focusedColumnNames)
{
    for (auto &columnName : focusedColumnNames) {
        focusedColumnNames_.insert(columnName);
    }
}

std::unordered_set<std::string> TriggerHelper::GetFocusedColumnNames() const
{
    return focusedColumnNames_;
}

std::vector<std::string> TriggerHelper::GetFocusedColumnNamesVec() const
{
    return std::vector<std::string>(focusedColumnNames_.begin(), focusedColumnNames_.end());
}

MediaLibraryTrigger::MediaLibraryTrigger()
{
    SetName("MediaLibraryTrigger");
}

bool MediaLibraryTrigger::Init(const std::vector<std::shared_ptr<MediaLibraryTriggerBase> >& triggers,
    const std::string& table)
{
    for (auto &trigger : triggers) {
        CHECK_AND_RETURN_RET_LOG(trigger, false, "there is nullptr trigger");
    }
    triggers_ = triggers;
    table_ = table;
    for (auto &trigger : triggers) {
        AddFocusedColumnName(trigger->GetFocusedColumnNames());
    }
    return true;
}

int32_t MediaLibraryTrigger::Process(std::shared_ptr<TransactionOperations> trans,
    const std::vector<AccurateRefresh::PhotoAssetChangeData>& changeDataVec)
{
    MEDIA_INFO_LOG("Process %{public}zu PhotoAssetChangeData with %{public}zu triggers",
        changeDataVec.size(), triggers_.size());
    CHECK_AND_RETURN_RET_LOG(trans, NativeRdb::E_ERROR, "input parameter trans is null");
    CHECK_AND_RETURN_RET_INFO_LOG(triggers_.size() && changeDataVec.size(), NativeRdb::E_OK,
        "0 triggers or 0 PhotoAssetChangeData");

    for (auto &changeData : changeDataVec) {
        MEDIA_DEBUG_LOG("Process PhotoAssetChangeData: %{public}s", changeData.ToString().c_str());
        if (!isTriggerFireForRow(trans, changeData)) {
            MEDIA_ERR_LOG("isTriggerFireForRow failed");
            return NativeRdb::E_ERROR;
        }
    }

    for (auto& trigger : triggers_) {
        MEDIA_INFO_LOG("%{public}s Postprocess", trigger->GetName().c_str());
        int32_t ret = trigger->Process(trans, changeDataVec);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "%{public}s PostProcess failed, ret:%{public}d", trigger->GetName().c_str(), ret);
    }
    return NativeRdb::E_OK;
}

bool MediaLibraryTrigger::isTriggerFireForRow(std::shared_ptr<TransactionOperations> trans,
    const AccurateRefresh::PhotoAssetChangeData& changeData)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    for (auto trigger : triggers_) {
        MEDIA_DEBUG_LOG("%{public}s process isTriggerFireForRow", trigger->GetName().c_str());
        if (!trigger->isTriggerFireForRow(trans, changeData)) {
            MEDIA_ERR_LOG("%{public}s isTriggerFireForRow failed", trigger->GetName().c_str());
            return false;
        }
    }
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo::IsValid() const
{
    return IsPackageNameValid() && IsLPathValid() && IsAlbumCntValid();
}

std::string InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo::ToString() const
{
    std::stringstream ss;
    ss << "packageName:" << packageName <<", ownerPackageName:" << ownerPackage << ", lPath:" << lPath \
        << ", albumCnt:" << albumCnt;
    return ss.str();
}

InsertSourcePhotoCreateSourceAlbumTrigger::InsertSourcePhotoCreateSourceAlbumTrigger()
{
    SetName("InsertSourcePhotoCreateSourceAlbumTrigger");
    AddFocusedColumnName({PhotoColumn::MEDIA_ID, MediaColumn::MEDIA_PACKAGE_NAME,
        PhotoColumn::PHOTO_OWNER_ALBUM_ID, MediaColumn::MEDIA_OWNER_PACKAGE});
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::QueryAlbumIdByLPath(std::shared_ptr<TransactionOperations> trans)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::vector<std::string> lPaths;
    for (const auto &[packageKey, packageInfo] : packageInfoMap_) {
        lPaths.push_back(packageInfo.lPath);
    }

    NativeRdb::RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.In(PhotoAlbumColumns::ALBUM_LPATH, lPaths);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, std::to_string(static_cast<int>(PhotoAlbumType::SOURCE)));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE,
        std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE_GENERIC));
    predicates.NotEqualTo(PhotoAlbumColumns::ALBUM_DIRTY,
        std::to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED)));
    MEDIA_INFO_LOG("query albumId by lpaths statement:%{public}s, lPaths:%{public}s",
        predicates.GetStatement().c_str(), MediaLibraryTriggerUtils::BracketVec(lPaths).c_str());

    auto resultSet = trans->QueryByStep(predicates, {PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_LPATH});
    CHECK_AND_RETURN_RET_LOG(MediaLibraryTriggerUtils::CheckResultSet(resultSet), false,
        "query albumId by lPaths failed");

    do {
        int32_t albumId = get<int32_t>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::ALBUM_ID, resultSet, TYPE_INT32));
        std::string lPath = get<std::string>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::ALBUM_LPATH, resultSet, TYPE_STRING));
        CHECK_AND_CONTINUE(!lPathAlbumIdMap_.count(lPath));
        lPathAlbumIdMap_[lPath] = albumId;
        MEDIA_INFO_LOG("lPath:%{public}s with albumId:%{public}d",
            lPath.c_str(), lPathAlbumIdMap_[lPath]);
    } while (resultSet->GoToNextRow() ==  NativeRdb::E_OK);
    resultSet->Close();
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::CheckValid() const
{
    bool valid = true;
    for (const auto&[packageKey, packageInfo] : packageInfoMap_) {
        MEDIA_DEBUG_LOG("packageInfo key: %{public}s, info: %{public}s",
            packageKey.c_str(), packageInfo.ToString().c_str());
        if (!packageInfo.IsValid()) {
            MEDIA_ERR_LOG("packageInfo with key: %{public}s is not valid, info: %{public}s",
                packageKey.c_str(), packageInfo.ToString().c_str());
            valid = false;
        }
    }
    return valid;
}


bool InsertSourcePhotoCreateSourceAlbumTrigger::UpdatePhotoOwnerAlbumId(std::shared_ptr<TransactionOperations> trans)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    if (!QueryAlbumIdByLPath(trans)) {
        MEDIA_ERR_LOG("fail to query albumId by lPath");
        return false;
    }
    std::string sql = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " +
        " CASE ";
    for (const auto &[packageKey, packageInfo] : packageInfoMap_) {
        CHECK_AND_RETURN_RET_LOG(lPathAlbumIdMap_.count(packageInfo.lPath), false,
            "%{public}s without albumId", packageKey.c_str());
        sql += " WHEN " + MediaColumn::MEDIA_PACKAGE_NAME + " = " +
            MediaLibraryTriggerUtils::WrapQuotation(packageInfo.packageName) +
            " AND " + MediaColumn::MEDIA_OWNER_PACKAGE + " = " +
            MediaLibraryTriggerUtils::WrapQuotation(packageInfo.ownerPackage) +
            " THEN " + std::to_string(lPathAlbumIdMap_[packageInfo.lPath]);
    }
    sql += " ELSE " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " END";
    sql += " WHERE " + PhotoColumn::MEDIA_ID + " IN " + MediaLibraryTriggerUtils::BracketVec(triggeredFileIds_);
    MEDIA_INFO_LOG("update owner-album id sql:%{public}s", sql.c_str());

    int ret = trans->ExecuteSql(sql);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK,
        false, "InsertSourcePhotoCreateSourceAlbumTrigger::UpdatePhotoOwnerAlbumId sql failed");
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::DeleteFromPhotoAlbum(std::shared_ptr<TransactionOperations> trans)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::vector<std::string> candidateLPaths;
    for (const auto &[packageKey, packageInfo] : packageInfoMap_) {
        CHECK_AND_RETURN_RET_LOG(packageInfo.IsAlbumCntValid(), false,
            "%{public}s without albumCnt", packageKey.c_str());
        CHECK_AND_RETURN_RET_LOG(packageInfo.IsLPathValid(), false,
            "%{public}s without lPath", packageKey.c_str());
        if (packageInfo.albumCnt > 0) {
            MEDIA_DEBUG_LOG("%{public}s with albumCnt:%{public}d does not need to delete album",
                packageKey.c_str(), packageInfo.albumCnt);
            continue;
        }
        candidateLPaths.push_back(packageInfo.lPath);
    }

    if (candidateLPaths.empty()) {
        MEDIA_INFO_LOG("no rows to delete from PhotoAlbum");
        return true;
    }

    NativeRdb::RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.In(PhotoAlbumColumns::ALBUM_LPATH, candidateLPaths);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, std::to_string(PhotoAlbumType::SOURCE));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, std::to_string(PhotoAlbumSubType::SOURCE_GENERIC));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_DIRTY, std::to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED)));
    MEDIA_INFO_LOG("delete from PhotoAlbum statement:%{public}s, lPaths:%{public}s",
        predicates.GetStatement().c_str(), MediaLibraryTriggerUtils::BracketVec(candidateLPaths).c_str());

    auto result = trans->Delete(predicates, PhotoAlbumColumns::ALBUM_ID);
    CHECK_AND_RETURN_RET_LOG(result.first == NativeRdb::E_OK, false,
        "fail to delete from photo album");
    MEDIA_ERR_LOG(" delete %{public}d rows from photo album", result.second.changed);
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::InsertIntoPhotoAlbum(std::shared_ptr<TransactionOperations> trans)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::vector<NativeRdb::ValuesBucket> values;
    for (auto &[packageKey, packageInfo] : packageInfoMap_) {
        CHECK_AND_RETURN_RET_LOG(packageInfo.IsAlbumCntValid(), false,
            "%{public}s without albumCnt", packageKey.c_str());
        CHECK_AND_RETURN_RET_LOG(packageInfo.IsLPathValid(), false,
            "%{public}s without lPath", packageKey.c_str());
        if (packageInfo.albumCnt > 0) {
            MEDIA_DEBUG_LOG("%{public}s does not need to insert into album", packageKey.c_str());
            continue;
        }
        NativeRdb::ValuesBucket value;
        value.PutInt(PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumType::SOURCE);
        value.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumSubType::SOURCE_GENERIC);
        value.PutString(PhotoAlbumColumns::ALBUM_NAME, packageInfo.packageName);
        value.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, packageInfo.ownerPackage);
        value.PutString(PhotoAlbumColumns::ALBUM_LPATH, packageInfo.lPath);
        value.PutInt(PhotoAlbumColumns::ALBUM_PRIORITY, ALBUM_PRIORITY_DEFAULT);
        value.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        value.PutLong(PhotoAlbumColumns::ALBUM_DATE_ADDED, MediaFileUtils::UTCTimeMilliSeconds());
        MEDIA_INFO_LOG("Candidate row to insert into PhotoAlbum: packageName:%{public}s,"
            " ownerPacakge:%{public}s, lpath:%{public}s", packageInfo.packageName.c_str(),
            packageInfo.ownerPackage.c_str(), packageInfo.lPath.c_str());
        values.push_back(value);
    }
    if (values.empty()) {
        MEDIA_ERR_LOG("no rows to insert into PhotoAlbum");
        return true;
    }
    int64_t insertedRows;
    AccurateRefresh::AlbumAccurateRefresh refresh(trans);
    auto ret = refresh.BatchInsert(insertedRows, PhotoAlbumColumns::TABLE, values);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, false, "fail to insert into PhotoAlbum, ret:%{public}d", ret);
    MEDIA_ERR_LOG("inserted rows %{public}lld into PhotoAlbum: ", insertedRows);
    refresh.Notify();
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::GetLPathFromAlbumPlugin(std::shared_ptr<TransactionOperations> trans,
    const std::string& packageName, const std::string& ownerPackage)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::string key = GetPackageNameAndOwnerPackageKey(packageName, ownerPackage);
    auto &packageInfo = packageInfoMap_[key];
    CHECK_AND_RETURN_RET_INFO_LOG(!packageInfo.IsLPathValid(), true,
        "lPath of %{public}s has been queried, lPath:%{public}s", key.c_str(), packageInfo.lPath.c_str());
    std::string sql = "SELECT COALESCE("
            "("
            " SELECT " + PhotoAlbumColumns::ALBUM_LPATH +  " FROM  album_plugin "
            "  WHERE"
            " ((bundle_name = " + MediaLibraryTriggerUtils::WrapQuotation(ownerPackage) + " AND COALESCE(" +
            MediaLibraryTriggerUtils::WrapQuotation(ownerPackage) + ", '') != '') OR " +
            PhotoAlbumColumns::ALBUM_NAME + " = " + MediaLibraryTriggerUtils::WrapQuotation(packageName) + ")" +
            "  AND priority = 1"
            "),"
            "'/Pictures/' ||  " + MediaLibraryTriggerUtils::WrapQuotation(packageName) + " "
          ")";
    MEDIA_INFO_LOG("get LPath from PhotoAlbum sql:%{public}s", sql.c_str());
    std::shared_ptr<NativeRdb::ResultSet> resultSet = trans->QueryByStep(sql);
    CHECK_AND_RETURN_RET_LOG(MediaLibraryTriggerUtils::CheckResultSet(resultSet), false,
        "fail to get LPath from PhotoAlbum for %{public}s", key.c_str());
    packageInfo.lPath = ResultSetUtils::GetStringValFromColumn(0, resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("key:%{public}s LPath:%{public}s", key.c_str(), packageInfo.lPath.c_str());
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::GetSourceAlbumCntByLPath(std::shared_ptr<TransactionOperations> trans,
    const std::string& packageName, const std::string& ownerPackage)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::string key = GetPackageNameAndOwnerPackageKey(packageName, ownerPackage);
    auto &packageInfo = packageInfoMap_[key];
    CHECK_AND_RETURN_RET_INFO_LOG(!packageInfo.IsAlbumCntValid(), true,
        "%{public}s album count has been queried, album count:%{public}d", key.c_str(), packageInfo.albumCnt);
    CHECK_AND_RETURN_RET_LOG(packageInfo.IsLPathValid(), false,
        "%{public}s without lPath", key.c_str());
    std::string sql =
        "SELECT COUNT(1) FROM " + PhotoAlbumColumns::TABLE + " WHERE LOWER(lpath) = LOWER(" +
        MediaLibraryTriggerUtils::WrapQuotation(packageInfo.lPath) + ")"
        " AND album_type = " + std::to_string(PhotoAlbumType::SOURCE) +
        " AND album_subtype = " + std::to_string(PhotoAlbumSubType::SOURCE_GENERIC) + " AND dirty != 4";
    MEDIA_ERR_LOG("query source album Count sql:%{public}s", sql.c_str());
    std::shared_ptr<NativeRdb::ResultSet> resultSet = trans->QueryByStep(sql);
    CHECK_AND_RETURN_RET_LOG(MediaLibraryTriggerUtils::CheckResultSet(resultSet), false,
        "fail to query source album Count for %{public}s", key.c_str());
    packageInfo.albumCnt = ResultSetUtils::GetIntValFromColumn(0, resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("key:%{public}s sourceAlbumCnt_:%{public}d", key.c_str(), packageInfo.albumCnt);
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::Notify()
{
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("failed to get MediaLibraryNotify");
        return false;
    }
    for (auto &[packageKey, packageInfo] : packageInfoMap_) {
        CHECK_AND_RETURN_RET_LOG(packageInfo.IsAlbumCntValid(), false,
            "%{public}s without albumCnt", packageKey.c_str());
        CHECK_AND_RETURN_RET_LOG(packageInfo.IsLPathValid(), false,
            "%{public}s without lPath", packageKey.c_str());
        CHECK_AND_RETURN_RET_LOG(lPathAlbumIdMap_.count(packageInfo.lPath), false,
            "%{public}s without albumId", packageKey.c_str());
        CHECK_AND_CONTINUE_INFO_LOG(packageInfo.albumCnt == 0,
            "%{public}s with albumCnt:%{public}d dont need to notify",
            packageKey.c_str(), packageInfo.albumCnt);

        std::string albumId = std::to_string(lPathAlbumIdMap_[packageInfo.lPath]);
        if (!all_of(albumId.begin(), albumId.end(), ::isdigit)) {
            MEDIA_ERR_LOG("Invalid albumId %{public}s", albumId.c_str());
            continue;
        }
        MEDIA_INFO_LOG("Notify key:%{public}s albumId:%{public}s", packageKey.c_str(), albumId.c_str());
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX, albumId),
            NotifyType::NOTIFY_ADD);
    }
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::CollectPackageInfo(std::shared_ptr<TransactionOperations> trans,
    const std::string& packageName, const std::string& ownerPackage)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::string hashKey = GetPackageNameAndOwnerPackageKey(packageName, ownerPackage);
    packageInfoMap_[hashKey].packageName = packageName;
    packageInfoMap_[hashKey].ownerPackage = ownerPackage;
    if (!GetLPathFromAlbumPlugin(trans, packageName, ownerPackage) ||
        !GetSourceAlbumCntByLPath(trans, packageName, ownerPackage)) {
        MEDIA_ERR_LOG("fail to collect info for %{public}s", hashKey.c_str());
        return false;
    }
    return true;
}

bool InsertSourcePhotoCreateSourceAlbumTrigger::isTriggerFireForRow(
    std::shared_ptr<TransactionOperations> trans, const AccurateRefresh::PhotoAssetChangeData& changeData)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::string packageName = changeData.infoAfterChange_.packageName_;
    std::string ownerPackage = changeData.infoAfterChange_.ownerPackage_;
    int32_t ownerAlbumId = changeData.infoAfterChange_.ownerAlbumId_;
    int32_t fileId = changeData.infoAfterChange_.fileId_;

    MEDIA_DEBUG_LOG("row info: packageName:%{public}s, ownerAlbumId:%{public}d,"
        "ownerPackage:%{public}s, fileId:%{public}d",
        packageName.c_str(), ownerAlbumId, ownerPackage.c_str(), fileId);

    CHECK_AND_RETURN_RET_INFO_LOG(packageName != "" && ownerAlbumId == 0, true,
        "fileId:%{public}d do not meet condition packageName:%{public}s ownerAlbumId:%{public}d",
        fileId, packageName.c_str(), ownerAlbumId);
    
    triggeredFileIds_.push_back(std::to_string(fileId));
    if (!CollectPackageInfo(trans, packageName, ownerPackage)) {
        MEDIA_ERR_LOG("fail to collect packageinfo");
        return false;
    }
    return true;
}

int32_t InsertSourcePhotoCreateSourceAlbumTrigger::Process(std::shared_ptr<TransactionOperations> trans,
    const std::vector<AccurateRefresh::PhotoAssetChangeData>& changeDataVec)
{
    CHECK_AND_RETURN_RET_LOG(trans, NativeRdb::E_ERROR, "input parameter trans is null");
    if (triggeredFileIds_.size() == 0 || changeDataVec.size() == 0) {
        MEDIA_INFO_LOG("0 triggered fileIds or 0 changeData");
        return NativeRdb::E_OK;
    }

    CHECK_AND_RETURN_RET_LOG(CheckValid(), NativeRdb::E_ERROR,
        "packageInfo is not valid");

    if (!DeleteFromPhotoAlbum(trans)|| !InsertIntoPhotoAlbum(trans) || !UpdatePhotoOwnerAlbumId(trans)  || !Notify()) {
        MEDIA_ERR_LOG("fail to process InsertSourcePhotoCreateSourceAlbumTrigger");
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

bool InsertPhotoUpdateAlbumBundleNameTrigger::PackageInfo::IsValid() const
{
    return packageName != "" && ownerPackage != "" &&
        albumWoBundleNameCnt != -1;
}

InsertPhotoUpdateAlbumBundleNameTrigger::InsertPhotoUpdateAlbumBundleNameTrigger()
{
    SetName("InsertPhotoUpdateAlbumBundleNameTrigger");
    AddFocusedColumnName({PhotoColumn::MEDIA_ID, MediaColumn::MEDIA_PACKAGE_NAME, MediaColumn::MEDIA_OWNER_PACKAGE});
}

int32_t InsertPhotoUpdateAlbumBundleNameTrigger::Process(std::shared_ptr<TransactionOperations> trans,
    const std::vector<AccurateRefresh::PhotoAssetChangeData>& insertedRowIds)
{
    CHECK_AND_RETURN_RET_LOG(trans, NativeRdb::E_ERROR, "input parameter trans is null");
    std::string sql = "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
        PhotoAlbumColumns::ALBUM_BUNDLE_NAME + " = " + " CASE ";
    std::vector<std::string> triggeredPackages;
    for (const auto &[packageName, packageInfo] : packageInfoMap_) {
        CHECK_AND_RETURN_RET_LOG(packageInfo.IsValid(), NativeRdb::E_ERROR,
            "%{public}s packageInfo is not valid", packageName.c_str());
        if (packageInfo.albumWoBundleNameCnt == 0) continue;
        triggeredPackages.push_back(packageName);
        sql += " WHEN " + PhotoAlbumColumns::ALBUM_NAME + " = " +
            MediaLibraryTriggerUtils::WrapQuotation(packageInfo.packageName) +
            " THEN " + MediaLibraryTriggerUtils::WrapQuotation(packageInfo.ownerPackage);
    }
    sql += " ELSE " + PhotoAlbumColumns::ALBUM_BUNDLE_NAME + " END" +
        " WHERE " + PhotoAlbumColumns::ALBUM_NAME + " IN " +
        MediaLibraryTriggerUtils::BracketVec(triggeredPackages, "'") +
        " AND " + PhotoAlbumColumns::ALBUM_TYPE + " = " + std::to_string(PhotoAlbumType::SOURCE) +
        " AND " +  PhotoAlbumColumns::ALBUM_SUBTYPE + " = "+
        std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE_GENERIC) +
        " AND " + PhotoAlbumColumns::ALBUM_BUNDLE_NAME + " IS NULL";
    if (triggeredPackages.empty()) {
        MEDIA_INFO_LOG("no package's BundleName to update");
        return NativeRdb::E_OK;
    }
    MEDIA_INFO_LOG("update PhotoAlbum BundleName sql:%{public}s", sql.c_str());

    int ret = trans->ExecuteSql(sql);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, NativeRdb::E_ERROR,
        "fail to update PhotoAlbum BundleName");
    return NativeRdb::E_OK;
}

bool InsertPhotoUpdateAlbumBundleNameTrigger::isAlbumWoBundleName(std::shared_ptr<TransactionOperations> trans,
    const std::string& packageName)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    auto& packageInfo = packageInfoMap_[packageName];
    if (packageInfo.IsValid()) {
        MEDIA_INFO_LOG("%{public}s already got albumWoBundleNameCnt:%{public}d",
            packageName.c_str(), packageInfo.albumWoBundleNameCnt);
        return true;
    }
    std::string sql = "SELECT COUNT(1) FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
        PhotoAlbumColumns::ALBUM_NAME + " = " + MediaLibraryTriggerUtils::WrapQuotation(packageName) +
        " AND " + PhotoAlbumColumns::ALBUM_TYPE + " = " + std::to_string(PhotoAlbumType::SOURCE) +
        " AND " +  PhotoAlbumColumns::ALBUM_SUBTYPE + " = " +
        std::to_string(OHOS::Media::PhotoAlbumSubType::SOURCE_GENERIC) +
        " AND " + PhotoAlbumColumns::ALBUM_BUNDLE_NAME + " IS NULL";
    MEDIA_INFO_LOG("query album without bundleName sql:%{public}s", sql.c_str());
    std::shared_ptr<NativeRdb::ResultSet> resultSet = trans->QueryByStep(sql);
    CHECK_AND_RETURN_RET_LOG(MediaLibraryTriggerUtils::CheckResultSet(resultSet), false,
        "fail to query album without bundleName");
    packageInfo.albumWoBundleNameCnt = ResultSetUtils::GetIntValFromColumn(0, resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("key:%{public}s albumWoBundleNameCnt:%{public}d",
        packageName.c_str(), packageInfo.albumWoBundleNameCnt);
    return true;
}

bool InsertPhotoUpdateAlbumBundleNameTrigger::isTriggerFireForRow(
    std::shared_ptr<TransactionOperations> trans, const AccurateRefresh::PhotoAssetChangeData& changeData)
{
    CHECK_AND_RETURN_RET_LOG(trans, false, "input parameter trans is null");
    std::string packageName = changeData.infoAfterChange_.packageName_;
    std::string ownerPackage = changeData.infoAfterChange_.ownerPackage_;

    MEDIA_DEBUG_LOG("packageName:%{public}s ownerPackage:%{public}s",
        packageName.c_str(), ownerPackage.c_str());
    CHECK_AND_RETURN_RET_INFO_LOG(packageName != "" && ownerPackage != "", true,
        "packageName:%{public}s, ownerPackage:%{public}s does not meet condition, ",
        packageName.c_str(), ownerPackage.c_str());
    packageInfoMap_[packageName].packageName = packageName;
    packageInfoMap_[packageName].ownerPackage = ownerPackage;
    
    if (!isAlbumWoBundleName(trans, packageName)) {
        MEDIA_ERR_LOG("fail to query album without bundleName");
        return false;
    }
    return true;
}
} // namespace Media
} // namespace OHOS