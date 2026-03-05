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
#include "clone_restore_selection_source.h"

#include "media_log.h"
#include "vision_db_sqls_more.h"
#include "media_upgrade.h"

namespace OHOS {
namespace Media {

const unordered_map<string, string> SELECTION_TABLE_CREATE_MAP = {
    { "tab_analysis_selection", "CREATE TABLE IF NOT EXISTS tab_analysis_selection (" \
        "file_id INTEGER PRIMARY KEY, " \
        "month_flag INTEGER, " \
        "year_flag INTEGER, " \
        "selection_version TEXT, " \
        "event_id INTEGER)" },
    { "tab_analysis_atom_event", "CREATE TABLE IF NOT EXISTS tab_analysis_atom_event (" \
        "event_id INTEGER PRIMARY KEY, " \
        "min_date INTEGER, " \
        "max_date INTEGER, " \
        "count INTEGER, " \
        "date_day INTEGER, " \
        "date_month INTEGER, " \
        "event_type INTEGER, " \
        "event_score INTEGER, " \
        "event_version TEXT, " \
        "event_status INTEGER)" },
    { "tab_analysis_total", "CREATE TABLE IF NOT EXISTS tab_analysis_total (" \
        "file_id INTEGER PRIMARY KEY, " \
        "selection INTEGER)" },
};

const unordered_map<string, SelectionInsertType> SELECTION_TABLE_INSERT_TYPE_MAP = {
    { PhotoColumn::PHOTOS_TABLE, SelectionInsertType::PHOTOS },
    { "tab_analysis_selection", SelectionInsertType::SELECTION },
    { "tab_analysis_atom_event", SelectionInsertType::ATOM_EVENT },
    { "tab_analysis_total", SelectionInsertType::ANALYSIS_TOTAL },
};

const string INSERT_PHOTO = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" + MediaColumn::MEDIA_ID + ", " +
    MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " +
    MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
    MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", " " +
    MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
    MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_DATE_TRASHED + ", " +
    MediaColumn::MEDIA_HIDDEN + ", " + PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
    PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_POSITION + ", " +
    PhotoColumn::PHOTO_SYNC_STATUS + ", " + PhotoColumn::PHOTO_CLEAN_FLAG + ", " +
    MediaColumn::MEDIA_TIME_PENDING + ", " + PhotoColumn::PHOTO_IS_TEMP + ")";

const string INSERT_SELECTION = "INSERT INTO tab_analysis_selection (file_id, month_flag, year_flag, selection_version, event_id)";
const string INSERT_ATOM_EVENT = "INSERT INTO tab_analysis_atom_event (event_id, min_date, max_date, count, date_day, " \
    "date_month, event_type, event_score, event_version, event_status)";
const string INSERT_ANALYSIS_TOTAL = "INSERT INTO tab_analysis_total (file_id, selection)";
const string VALUES_BEGIN = " VALUES (";
const string VALUES_END = ") ";

void CloneRestoreSelectionOpenCall::Init(const vector<string> &tableList)
{
    for (const auto &tableName : tableList) {
        if (SELECTION_TABLE_CREATE_MAP.count(tableName) == 0) {
            MEDIA_INFO_LOG("Find value failed: %{public}s, skip", tableName.c_str());
            continue;
        }
        string createSql = SELECTION_TABLE_CREATE_MAP.at(tableName);
        createSqls_.push_back(createSql);
    }
}

int32_t CloneRestoreSelectionOpenCall::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    for (const auto &createSql : createSqls_) {
        int32_t errCode = rdbStore.ExecuteSql(createSql);
        if (errCode != NativeRdb::E_OK) {
            MEDIA_INFO_LOG("Execute %{public}s failed: %{public}d", createSql.c_str(), errCode);
            return errCode;
        }
    }
    return NativeRdb::E_OK;
}

int32_t CloneRestoreSelectionOpenCall::OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return 0;
}

void CloneRestoreSelectionSource::Init(const string &dbPath, const vector<string> &tableList)
{
    NativeRdb::RdbStoreConfig config(dbPath);
    CloneRestoreSelectionOpenCall helper;
    helper.Init(tableList);
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    this->cloneStorePtr_ = store;
    Insert(tableList, this->cloneStorePtr_);
}

void CloneRestoreSelectionSource::Insert(const vector<string> &tableList, std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    for (const auto &tableName : tableList) {
        if (SELECTION_TABLE_INSERT_TYPE_MAP.count(tableName) == 0) {
            MEDIA_INFO_LOG("Find value failed: %{public}s, skip", tableName.c_str());
            continue;
        }
        SelectionInsertType insertType = SELECTION_TABLE_INSERT_TYPE_MAP.at(tableName);
        InsertByType(insertType, rdbPtr);
    }
}

void CloneRestoreSelectionSource::InsertByType(SelectionInsertType insertType, std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    switch (insertType) {
        case SelectionInsertType::PHOTOS: {
            InsertPhoto(rdbPtr);
            break;
        }
        case SelectionInsertType::SELECTION: {
            InsertSelection(rdbPtr);
            break;
        }
        case SelectionInsertType::ATOM_EVENT: {
            InsertAtomEvent(rdbPtr);
            break;
        }
        case SelectionInsertType::ANALYSIS_TOTAL: {
            InsertAnalysisTotal(rdbPtr);
            break;
        }
        default:
            break;
    }
}

void CloneRestoreSelectionSource::InsertPhoto(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "1, " +
        "'/storage/cloud/files/Photo/16/test.jpg', 175258, 'test', 'test.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205218, 1501924205423, 1501924205, 0, 0, 0, 0, " +
        "1280, 960, 0, 1, 0, 0, 0, 0" + VALUES_END);
}

void CloneRestoreSelectionSource::InsertSelection(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_SELECTION + VALUES_BEGIN +
        "1, 1, 1, 'v1.0', 100" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_SELECTION + VALUES_BEGIN +
        "2, 0, 1, 'v1.0', 101" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_SELECTION + VALUES_BEGIN +
        "3, 1, 0, 'v1.0', 102" + VALUES_END);
}

void CloneRestoreSelectionSource::InsertAtomEvent(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_ATOM_EVENT + VALUES_BEGIN +
        "100, 1501924205000, 1501924206000, 5, 20240304, 202403, 1, 95, 'v1.0', 1" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_ATOM_EVENT + VALUES_BEGIN +
        "101, 1501924207000, 1501924208000, 3, 20240305, 202403, 2, 90, 'v1.0', 1" + VALUES_END);
}

void CloneRestoreSelectionSource::InsertAnalysisTotal(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_TOTAL + VALUES_BEGIN + "1, 1" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_TOTAL + VALUES_BEGIN + "2, 0" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_TOTAL + VALUES_BEGIN + "3, 1" + VALUES_END);
}

}
}