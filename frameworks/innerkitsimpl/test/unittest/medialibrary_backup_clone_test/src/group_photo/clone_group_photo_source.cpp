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

#include "clone_group_photo_source.h"

#include <utility>
#include "media_log.h"
#define private public
#define protected public
#include "medialibrary_unistore.h"
#undef private
#undef protected
using namespace std;

namespace OHOS {
namespace Media {
void CloneGroupPhotoOpenCall::Init(const vector<string> &tableList)
{
    for (const auto &tableName : tableList) {
        if (TABLE_CREATE_MAP.count(tableName) == 0) {
            MEDIA_INFO_LOG("Find value failed: %{public}s, skip", tableName.c_str());
            continue;
        }
        string createSql = TABLE_CREATE_MAP.at(tableName);
        createSqls_.push_back(createSql);
    }
}

int32_t CloneGroupPhotoOpenCall::OnCreate(NativeRdb::RdbStore &rdbStore)
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

int32_t CloneGroupPhotoOpenCall::OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return 0;
}

void CloneGroupPhotoSource::Init(const string &dbPath, const vector<string> &tableList)
{
    NativeRdb::RdbStoreConfig config(dbPath);
    CloneGroupPhotoOpenCall helper;
    helper.Init(tableList);
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    this->cloneStorePtr_ = store;
    Insert(tableList, this->cloneStorePtr_);
}

void CloneGroupPhotoSource::InitWithoutData(const string &dbPath, const vector<string> &tableList)
{
    NativeRdb::RdbStoreConfig config(dbPath);
    CloneGroupPhotoOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    this->cloneStorePtr_ = store;
}

void CloneGroupPhotoSource::Insert(const vector<string> &tableList, std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    for (const auto &tableName : tableList) {
        if (TABLE_INSERT_TYPE_MAP.count(tableName) == 0) {
            MEDIA_INFO_LOG("Find value failed: %{public}s, skip", tableName.c_str());
            continue;
        }
        InsertType insertType = TABLE_INSERT_TYPE_MAP.at(tableName);
        InsertByType(insertType, rdbPtr);
    }
}

void CloneGroupPhotoSource::InsertByType(InsertType insertType, std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    switch (insertType) {
        case InsertType::PHOTOS: {
            InsertPhoto(rdbPtr);
            break;
        }
        case InsertType::ANALYSIS_ALBUM: {
            InsertAnalysisAlbum(rdbPtr);
            break;
        }
        case InsertType::ANALYSIS_PHOTO_MAP: {
            InsertAnalysisPhotoMap(rdbPtr);
            break;
        }
        default:
            break;
    }
}

void CloneGroupPhotoSource::InsertPhoto(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "1, " +
        "'/storage/cloud/files/Photo/16/test.jpg', 175258, 'test', 'test.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205218, 1501924205423, 1501924205, 0, 0, 0, 0, " +
        "1280, 960, 0, '1'" + VALUES_END); // cam, pic, shootingmode = 1
    rdbPtr->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "2, " +
        "'/storage/cloud/files/Photo/1/IMG_1501924307_001.jpg', 175397, 'test_002', 'test_002.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924207184, 1501924207286, 1501924207, 0, 0, 0, 0, " +
        "1280, 960, 0, ''" + VALUES_END); // cam, pic, trashed
}

void CloneGroupPhotoSource::InsertAnalysisAlbum(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql("INSERT INTO AnalysisAlbum ("
        "album_type, album_subtype, album_name, tag_id, cover_uri, is_cover_satisfied) "
        "VALUES (4096, 4103, 'test_group_photo_album_001', 'a|b,', 'file://media/Photo/1/IMG/test.jpg', 1)");
    rdbPtr->ExecuteSql("INSERT INTO AnalysisAlbum ("
        "album_type, album_subtype, album_name, tag_id, cover_uri, is_cover_satisfied, count) "
        "VALUES (4096, 4103, '', 'a|c,', "
        "'file://media/Photo/2/IMG_002/test_002.jpg', 1, 2)");
    rdbPtr->ExecuteSql("INSERT INTO AnalysisAlbum ("
        "album_type, album_subtype, album_name, tag_id, cover_uri, is_cover_satisfied) "
        "VALUES (4096, 4102, 'test_portrait_album_001', 'a', 'test_cover_uri', 1)");
}

void CloneGroupPhotoSource::InsertAnalysisPhotoMap(std::shared_ptr<NativeRdb::RdbStore> rdbPtr)
{
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_PHOTO_MAP + VALUES_BEGIN + "1, 1, 1" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_PHOTO_MAP + VALUES_BEGIN + "1, 2, 2" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_PHOTO_MAP + VALUES_BEGIN + "2, 1, 1" + VALUES_END);
    rdbPtr->ExecuteSql(INSERT_ANALYSIS_PHOTO_MAP + VALUES_BEGIN + "2, 2, 2" + VALUES_END);
}

}
}