/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "ChangeRequestRevertSetDisplayNameTest"

#include "change_request_revert_setdisplayname_test.h"

#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "file_asset.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_photo_operations.h"
#include "fetch_result.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "rdb_utils.h"
#include "uri.h"
#include "userfilemgr_uri.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace std;
using namespace testing::ext;
using OHOS::DataShare::DataShareValuesBucket;
using OHOS::DataShare::DataSharePredicates;
using namespace OHOS::RdbDataShareAdapter;

const std::string SET_DISPLAY_NAME_KEY = "set_displayName";
const std::string CAN_FALLBACK = "can_fallback";
const std::string OLD_DISPLAY_NAME = "old_displayName";
const std::string API_VERSION = "api_version";

const std::string INSERT_PHOTO = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" + MediaColumn::MEDIA_ID + ", " +
                                 MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_TITLE + ", " +
                                 MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_MIME_TYPE + ", " +
                                 MediaColumn::MEDIA_TYPE + ", " + PhotoColumn::PHOTO_MEDIA_SUFFIX + ", " +
                                 PhotoColumn::PHOTO_SUBTYPE + ", " + MediaColumn::MEDIA_DATE_TAKEN + ")";

const std::string VALUES_BEGIN = " VALUES (";
const string VALUES_END = ") ";

const std::string PHOTO_AEERT_REAL_NAME = "IMG_1501924305_000.jpg";
const std::string OLD_PHOTO_AEERT_DISPLAY_NAME = "old_photo_asset.jpg";
const std::string NEW_PHOTO_AEERT_DISPLAY_NAME = "new_photo_asset.heif";

const std::string VIDEO_AEERT_REAL_NAME = "IMG_1501924305_000.mp4";
const std::string OLD_VIDEO_AEERT_DISPLAY_NAME = "old_video_asset.mp4";
const std::string NEW_VIDEO_AEERT_DISPLAY_NAME = "new_video_asset.avi";

const std::string OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME = "old_moving_photo_asset.jpg";
const std::string NEW_MOVING_PHOTO_AEERT_DISPLAY_NAME = "new_moving_photo_asset.heif";

const std::string OLD_PHOTO_PATH = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
const std::string OLD_VIDEO_PATH = "/storage/cloud/files/Photo/16/VID_1742022530_004.mp4";

// file_id,
// data, title, display_name, mime_type, media_suffix, meta_date_modified, last_visit_time
const std::string INSERT_PHOTO_AEERT =
    INSERT_PHOTO + VALUES_BEGIN + "1, " +
    "'/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg', 'old_photo_asset', 'old_photo_asset.jpg', " +
    "'image/jpeg', 1, 'jpg', 0, " + to_string(MediaFileUtils::UTCTimeMilliSeconds()) + VALUES_END;

const std::string INSERT_VIDEO_PHOTO_AEERT =
    INSERT_PHOTO + VALUES_BEGIN + "1, " +
    "'/storage/cloud/files/Photo/16/VID_1742022530_004.mp4', 'old_video_asset', 'old_video_asset.mp4', " +
    "'video/mp4', 2, 'mp4', 0, " + to_string(MediaFileUtils::UTCTimeMilliSeconds()) + VALUES_END;

const std::string DELETE_DATA = "DELETE FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE file_id = 1";

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
void InitTables()
{
    std::vector<std::string> createTableSqlList = { PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbstore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void ClearTestTables()
{
    std::vector<std::string> dropTableList = { PhotoColumn::PHOTOS_TABLE };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbstore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

void CleanAndRestart()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    system("rm -rf /storage/cloud/files/.thumbs");
    system("rm -rf /storage/cloud/files/.editData");
    system("rm -rf /storage/cloud/files/.cache");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/cloud/100/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    ClearTestTables();
    InitTables();
}

void ChangeRequestRevertSetDisplayNameTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("start SetDisplayNameTest");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    InitTables();
    MEDIA_INFO_LOG("setDisplayNameTest::SetUpTestCase:: Finish");
}

void ChangeRequestRevertSetDisplayNameTest::TearDownTestCase()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }
    CleanAndRestart();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("SetDisplayNameTest Clean is finish");
}

void ChangeRequestRevertSetDisplayNameTest::SetUp()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start SetDisplayNameTest failed, can not get rdbstore");
        exit(1);
    }
    CleanAndRestart();
}

void ChangeRequestRevertSetDisplayNameTest::TearDown()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start SetDisplayNameTest failed, can not get rdbstore");
        exit(1);
    }
    int32_t ret = g_rdbStore->ExecuteSql(DELETE_DATA);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Execute sql %{public}s failed", DELETE_DATA.c_str());
        return;
    }
}

std::unique_ptr<FileAsset> QueryAssetFromFileId(const std::string &fileId)
{
    std::string querySql = "SELECT * FROM " + PhotoColumn::PHOTOS_TABLE +
        " WHERE " + MediaColumn::MEDIA_ID + " = " + fileId;
    EXPECT_NE((g_rdbStore == nullptr), true);
    auto resultSet = g_rdbStore->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Get resultSet failed");
        return nullptr;
    }

    int32_t resultSetCount = 0;
    int32_t ret = resultSet->GetRowCount(resultSetCount);
    if (ret != NativeRdb::E_OK || resultSetCount <= 0) {
        MEDIA_ERR_LOG("resultSet row count is 0");
        return nullptr;
    }

    std::shared_ptr<FetchResult<FileAsset>> fetchFileResult = make_shared<FetchResult<FileAsset>>();
    if (fetchFileResult == nullptr) {
        MEDIA_ERR_LOG("Get fetchFileResult failed");
        return nullptr;
    }
    auto fileAsset = fetchFileResult->GetObjectFromRdb(resultSet, 0);
    if (fileAsset == nullptr || fileAsset->GetId() < 0) {
        return nullptr;
    }
    return fileAsset;
}

void UriAddKeyValue(std::string &uri, const std::string &key, std::string value)
{
    string uriKey = key + '=';
    if (uri.find(uriKey) != string::npos) {
        return;
    }

    char queryMark = (uri.find('?') == string::npos) ? '?' : '&';
    string append = queryMark + key + '=' + value;

    size_t pos = uri.find('#');
    if (pos == string::npos) {
        uri += append;
    } else {
        uri.insert(pos, append);
    }
}

int32_t UpdateFileAssetBySetDisplayname(const std::string &newDisplayName, const std::string &isCanFallback,
    const std::string &oldDisplayName, const int32_t fileId)
{
    std::string uri = PAH_UPDATE_PHOTO;
    UriAddKeyValue(uri, API_VERSION, std::to_string(MEDIA_API_VERSION_V10));
    UriAddKeyValue(uri, SET_DISPLAY_NAME_KEY, newDisplayName);
    UriAddKeyValue(uri, CAN_FALLBACK, isCanFallback);
    UriAddKeyValue(uri, OLD_DISPLAY_NAME, oldDisplayName);
    Uri updateAssetUri(uri);

    MediaLibraryCommand cmd(updateAssetUri);
    
    DataShare::DataShareValuesBucket values;
    values.Put(MediaColumn::MEDIA_NAME, newDisplayName);
    std::string newTitle = MediaFileUtils::GetTitleFromDisplayName(newDisplayName);
    values.Put(MediaColumn::MEDIA_TITLE, newTitle);
    
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(PhotoColumn::MEDIA_ID + " = " + std::to_string(fileId));

    return MediaLibraryDataManager::GetInstance()->Update(cmd, values, predicates);
}

string GetFilePath(int fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return "";
    }

    vector<string> columns = { PhotoColumn::MEDIA_FILE_PATH };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return "";
    }
    auto resultSet = g_rdbStore->Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file Path");
        return "";
    }
    string path = GetStringVal(PhotoColumn::MEDIA_FILE_PATH, resultSet);
    return path;
}

int32_t MakePhotoUnpending(int fileId, bool isMovingPhoto = false)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_INVALID_FILEID;
    }

    string path = GetFilePath(fileId);
    if (path.empty()) {
        MEDIA_ERR_LOG("Get path failed");
        return E_INVALID_VALUES;
    }
    int32_t errCode = MediaFileUtils::CreateAsset(path);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Can not create asset");
        return errCode;
    }

    if (isMovingPhoto) {
        string videoPath = MediaFileUtils::GetMovingPhotoVideoPath(path);
        errCode = MediaFileUtils::CreateAsset(videoPath);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Can not create video asset");
            return errCode;
        }
    }

    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket values;
    values.PutLong(PhotoColumn::MEDIA_TIME_PENDING, 0);
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t changedRows = -1;
    errCode = g_rdbStore->Update(cmd, changedRows);
    if (errCode != E_OK || changedRows <= 0) {
        MEDIA_ERR_LOG("Update pending failed, errCode = %{public}d, changeRows = %{public}d",
            errCode, changedRows);
        return errCode;
    }

    return E_OK;
}

int32_t CreatePhotoApi10(int mediaType, const string &displayName, bool isMovingPhoto = false)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_NAME, displayName);
    values.PutInt(MediaColumn::MEDIA_TYPE, mediaType);
    if (isMovingPhoto) {
        values.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    }
    cmd.SetValueBucket(values);
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    if (ret < 0) {
        MEDIA_ERR_LOG("Create Photo failed, errCode=%{public}d", ret);
        return ret;
    }
    return ret;
}

int32_t SetDefaultPhotoApi10(int mediaType, const string &displayName, bool isMovingPhoto = false)
{
    int fileId = CreatePhotoApi10(mediaType, displayName, isMovingPhoto);
    if (fileId < 0) {
        MEDIA_ERR_LOG("create photo failed, res=%{public}d", fileId);
        return fileId;
    }
    int32_t errCode = MakePhotoUnpending(fileId, isMovingPhoto);
    if (errCode != E_OK) {
        return errCode;
    }
    return fileId;
}

int32_t OpenCacheFile(bool isVideo, string &fileName)
{
    string extension = isVideo ? ".mp4" : ".jpg";
    fileName = to_string(MediaFileUtils::UTCTimeNanoSeconds()) + extension;
    string uri = PhotoColumn::PHOTO_CACHE_URI_PREFIX + fileName;
    UriAddKeyValue(uri, URI_PARAM_API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri openCacheUri(uri);

    MediaLibraryCommand cmd(openCacheUri);
    cmd.SetOprnObject(OperationObject::FILESYSTEM_PHOTO);
    int32_t fd = MediaLibraryDataManager::GetInstance()->OpenFile(cmd, "w");
    if (fd <= 0) {
        MEDIA_ERR_LOG("Open file failed, fd=%{public}d", fd);
    }
    close(fd);
    return fd;
}

int32_t MovingPhotoEditByCache(int32_t fileId, string &fileName, string &videoFileName, bool isGraffiti = false)
{
    string uri = PAH_SUBMIT_CACHE;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileId);
    valuesBucket.Put(CACHE_FILE_NAME, fileName);
    if (!isGraffiti) {
        valuesBucket.Put(CACHE_MOVING_PHOTO_VIDEO_NAME, videoFileName);
    }
    valuesBucket.Put(COMPATIBLE_FORMAT, "compatibleFormat");
    valuesBucket.Put(FORMAT_VERSION, "formatVersion");
    valuesBucket.Put(EDIT_DATA, "data");

    MediaLibraryCommand submitCacheCmd(OperationObject::FILESYSTEM_PHOTO,
        OperationType::SUBMIT_CACHE, MediaLibraryApi::API_10);
    return MediaLibraryDataManager::GetInstance()->Insert(submitCacheCmd, valuesBucket);
}

int32_t UpdateEditTime(int64_t fileId, int64_t time)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    MediaLibraryCommand updatePendingCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    updatePendingCmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, to_string(fileId));
    ValuesBucket updateValues;
    updateValues.PutLong(PhotoColumn::PHOTO_EDIT_TIME, time);
    updatePendingCmd.SetValueBucket(updateValues);
    int32_t rowId = 0;
    int32_t result = rdbStore->Update(updatePendingCmd, rowId);
    if (result != NativeRdb::E_OK || rowId <= 0) {
        MEDIA_ERR_LOG("Update File pending failed. Result %{public}d.", result);
        return E_HAS_DB_ERROR;
    }

    return E_OK;
}

int32_t SetPendingOnly(int32_t pendingTime, int32_t fileId)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    ValuesBucket values;
    values.PutLong(PhotoColumn::MEDIA_TIME_PENDING, pendingTime);
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t changedRows = -1;
    int32_t errCode = g_rdbStore->Update(cmd, changedRows);
    if (errCode != E_OK || changedRows <= 0) {
        MEDIA_ERR_LOG("Update pending failed, errCode = %{public}d, changeRows = %{public}d",
            errCode, changedRows);
        return errCode;
    }

    return E_OK;
}

/**
 * @tc.name: Revert_SetDisplayName_PhotoAsset_001
 * @tc.desc:  photoasset SetDisplayName after editdata, can revert, expect revert success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestRevertSetDisplayNameTest, Revert_SetDisplayName_PhotoAsset_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd Revert_SetDisplayName_PhotoAsset_001");
    int32_t fileId = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, OLD_PHOTO_AEERT_DISPLAY_NAME);
    if (fileId < 0) {
        MEDIA_ERR_LOG("Create photo failed error=%{public}d", fileId);
        return;
    }

    // open photo and video file
    string fileName;
    int32_t fd = OpenCacheFile(false, fileName);
    EXPECT_GE(fd, 0);

    // edit by cache
    int32_t ret = MovingPhotoEditByCache(fileId, fileName, fileName, true);
    EXPECT_EQ(ret, fileId); // when write moving photo to photo directory, check moving photo failed
    UpdateEditTime(fileId, MediaFileUtils::UTCTimeSeconds());
    auto oldFileAsset = QueryAssetFromFileId(std::to_string(fileId));

    ret = UpdateFileAssetBySetDisplayname(NEW_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_PHOTO_AEERT_DISPLAY_NAME, fileId);
    EXPECT_GE(ret, 0);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::REVERT_EDIT,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, fileId);
    cmd.SetValueBucket(values);
    ret = SetPendingOnly(0, fileId);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(MediaLibraryPhotoOperations::RevertToOrigin(cmd), E_OK);
    MEDIA_INFO_LOG("end tdd Revert_SetDisplayName_PhotoAsset_001");
}

/**
 * @tc.name: Revert_SetDisplayName_PhotoAsset_002
 * @tc.desc:  moving photoasset SetDisplayName when addresource, can revert, expect revert success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestRevertSetDisplayNameTest, Revert_SetDisplayName_PhotoAsset_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd Revert_SetDisplayName_PhotoAsset_002");
    int32_t fileId = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_IMAGE, OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME, true);
    if (fileId < 0) {
        MEDIA_ERR_LOG("Create photo failed error=%{public}d", fileId);
        return;
    }

    // open photo and video file
    string fileName;
    int32_t fd = OpenCacheFile(false, fileName);
    EXPECT_GE(fd, 0);

    string videoFileName;
    int32_t videoFd = OpenCacheFile(true, videoFileName);
    EXPECT_GE(videoFd, 0);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::REVERT_EDIT,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, fileId);
    cmd.SetValueBucket(values);
    int32_t ret = SetPendingOnly(0, fileId);
    EXPECT_EQ(ret, 0);

    // edit by cache
    ret = MovingPhotoEditByCache(fileId, fileName, videoFileName);
    EXPECT_EQ(ret, E_FILE_OPER_FAIL);

    UpdateEditTime(fileId, MediaFileUtils::UTCTimeSeconds());
    EXPECT_EQ(MediaLibraryPhotoOperations::RevertToOrigin(cmd), E_OK);

    // graffiti edit by cache
    ret = MovingPhotoEditByCache(fileId, fileName, videoFileName, true);
    EXPECT_EQ(ret, fileId);

    ret = UpdateFileAssetBySetDisplayname(
        NEW_MOVING_PHOTO_AEERT_DISPLAY_NAME, "0", OLD_MOVING_PHOTO_AEERT_DISPLAY_NAME, fileId);
    EXPECT_GE(ret, 0);


    EXPECT_EQ(MediaLibraryPhotoOperations::RevertToOrigin(cmd), E_OK);
    MEDIA_INFO_LOG("end tdd Revert_SetDisplayName_PhotoAsset_002");
}

/**
 * @tc.name: Revert_SetDisplayName_PhotoAsset_003
 * @tc.desc:  vedio SetDisplayName when addresource, can revert, expect revert success
 * @tc.type: FUNC
 */
HWTEST_F(ChangeRequestRevertSetDisplayNameTest, Revert_SetDisplayName_PhotoAsset_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd Revert_SetDisplayName_PhotoAsset_003");
    int32_t fileId = SetDefaultPhotoApi10(MediaType::MEDIA_TYPE_VIDEO, OLD_VIDEO_AEERT_DISPLAY_NAME, true);
    if (fileId < 0) {
        MEDIA_ERR_LOG("Create photo failed error=%{public}d", fileId);
        return;
    }

    // open photo and video file
    string fileName;
    int32_t fd = OpenCacheFile(false, fileName);
    EXPECT_GE(fd, 0);

    string videoFileName;
    int32_t videoFd = OpenCacheFile(true, videoFileName);
    EXPECT_GE(videoFd, 0);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::REVERT_EDIT,
        MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_ID, fileId);
    cmd.SetValueBucket(values);
    int32_t ret = SetPendingOnly(0, fileId);
    EXPECT_EQ(ret, 0);

    // edit by cache
    ret = MovingPhotoEditByCache(fileId, fileName, videoFileName);
    EXPECT_EQ(ret, E_FILE_OPER_FAIL);

    UpdateEditTime(fileId, MediaFileUtils::UTCTimeSeconds());
    EXPECT_EQ(MediaLibraryPhotoOperations::RevertToOrigin(cmd), E_OK);

    // graffiti edit by cache
    ret = MovingPhotoEditByCache(fileId, fileName, videoFileName, true);
    EXPECT_EQ(ret, fileId);

    ret = UpdateFileAssetBySetDisplayname(NEW_VIDEO_AEERT_DISPLAY_NAME, "0", OLD_VIDEO_AEERT_DISPLAY_NAME, fileId);
    EXPECT_GE(ret, 0);


    EXPECT_EQ(MediaLibraryPhotoOperations::RevertToOrigin(cmd), E_OK);
    MEDIA_INFO_LOG("end tdd Revert_SetDisplayName_PhotoAsset_003");
}

} // namespace Media
} // namespace OHOS