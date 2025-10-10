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

#define MLOG_TAG "MediaAssetsControllerServiceTest"

#include "set_user_comment_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "datashare_result_set.h"
#include "media_assets_controller_service.h"
#include "media_assets_service.h"
#include "rdb_utils.h"
#undef private
#undef protected

#include "create_asset_vo.h"
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;

static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear album table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void SetUserCommentTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void SetUserCommentTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void SetUserCommentTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void SetUserCommentTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

using ServiceCall = std::function<void(MessageParcel &data, MessageParcel &reply)>;

static int32_t ServiceCreateAsset(CreateAssetReqBody &reqBody, ServiceCall call)
{
    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    call(data, reply);

    IPC::MediaRespVo<CreateAssetRespBody> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }

    int32_t errCode = respVo.GetErrCode();
    if (errCode != 0) {
        MEDIA_ERR_LOG("respVo.GetErrCode: %{public}d", errCode);
        return errCode;
    }

    return respVo.GetBody().fileId;
}
static int32_t PublicCreateAsset(const std::string &ext, const std::string &title = "")
{
    CreateAssetReqBody reqBody;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.title = title;
    reqBody.extension = ext;

    ServiceCall call = [](MessageParcel &data, MessageParcel &reply) {
        auto service = make_shared<MediaAssetsControllerService>();
        service->PublicCreateAsset(data, reply);
    };

    return ServiceCreateAsset(reqBody, call);
}

static int32_t SystemCreateAsset(
    const std::string &displayName, int32_t photoSubtype, const std::string &cameraShotKey = "")
{
    CreateAssetReqBody reqBody;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.photoSubtype = photoSubtype;
    reqBody.displayName = displayName;
    reqBody.cameraShotKey = cameraShotKey;

    ServiceCall call = [](MessageParcel &data, MessageParcel &reply) {
        auto service = make_shared<MediaAssetsControllerService>();
        service->SystemCreateAsset(data, reply);
    };

    return ServiceCreateAsset(reqBody, call);
}

static void InsertHeifAsset()
{
    std::string insertSql = R"S(INSERT INTO Photos(data, size, title, display_name, media_type, position, is_temp,
        time_pending, hidden, date_trashed, transcode_time, trans_code_file_size, exist_compatible_duplicate)
        VALUES ('/storage/cloud/files/Photo/665/test.heic', 7879, 'test',
        'test.heic', 1, 0, 0, 0, 0, 0, 1501838589870, 348113, 1))S";
    int32_t ret = g_rdbStore->ExecuteSql(insertSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Execute sql %{public}s failed", insertSql.c_str());
    }
}

static int32_t QueryFileIdByDisplayName(const string &displayName)
{
    vector<string> columns;
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_NAME, displayName);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get fileId");
        return -1;
    }
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    return fileId;
}

static int32_t QueryTransCodeInfoByID(const int32_t fileId, std::shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    vector<string> columns = { PhotoColumn::PHOTO_TRANSCODE_TIME, PhotoColumn::PHOTO_TRANS_CODE_FILE_SIZE,
        PhotoColumn::PHOTO_EXIST_COMPATIBLE_DUPLICATE };
    resultSet = MediaLibraryRdbStore::Query(rdbPredicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Read moving photo query photo id by display name failed");
        return -1;
    }
    return 0;
}

HWTEST_F(SetUserCommentTest, SetUserCommentTest_Test_001, TestSize.Level0)
{
    int32_t fileId = PublicCreateAsset("jpg");
    ASSERT_GT(fileId, 0);
    const std::string userComment = "user comment";

    AssetChangeReqBody reqBody;
    reqBody.fileId = fileId;
    reqBody.userComment = "user comment";
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);

    auto service = make_shared<MediaAssetsControllerService>();
    service->AssetChangeSetUserComment(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> resp;
    bool isValid = resp.Unmarshalling(reply);
    ASSERT_EQ(isValid, true);
    int32_t changedRows = resp.GetErrCode();
    EXPECT_EQ(changedRows, 1); // 修改了1行

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    using namespace RdbDataShareAdapter;
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, PhotoColumn::PHOTOS_TABLE);
    std::vector<std::string> columns { PhotoColumn::PHOTO_USER_COMMENT };

    shared_ptr<NativeRdb::ResultSet> resSet = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
    EXPECT_NE(resSet, nullptr);
    EXPECT_EQ(resSet->GoToNextRow(), NativeRdb::E_OK);
    int commentIdx = -1;
    resSet->GetColumnIndex(PhotoColumn::PHOTO_USER_COMMENT, commentIdx);
    std::string comment;
    resSet->GetString(commentIdx, comment);
    EXPECT_EQ(comment, userComment);
}

HWTEST_F(SetUserCommentTest, SetUserCommentTest_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetUserCommentTest_Test_002");
    system("mkdir -p /storage/cloud/files/Photo/665/");
    system("touch /storage/cloud/files/Photo/665/test.heic");
    system("mkdir -p /storage/cloud/files/.editData/Photo/665/test.heic");
    system("touch /storage/cloud/files/.editData/Photo/665/test.heic/transcode.jpg");

    InsertHeifAsset();
    int32_t fileId = QueryFileIdByDisplayName("test.heic");
    ASSERT_GT(fileId, 0);

    std::shared_ptr<NativeRdb::ResultSet> resultSet =nullptr;
    ASSERT_EQ(QueryTransCodeInfoByID(fileId, resultSet), 0);
    EXPECT_EQ(GetInt64Val(PhotoColumn::PHOTO_TRANSCODE_TIME, resultSet), 1501838589870);
    EXPECT_EQ(GetInt64Val(PhotoColumn::PHOTO_TRANS_CODE_FILE_SIZE, resultSet), 348113);
    EXPECT_EQ(GetInt32Val(PhotoColumn::PHOTO_EXIST_COMPATIBLE_DUPLICATE, resultSet), 1);

    const std::string userComment = "user comment";
    AssetChangeReqBody reqBody;
    reqBody.fileId = fileId;
    reqBody.userComment = "user comment";
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);

    auto service = make_shared<MediaAssetsControllerService>();
    service->AssetChangeSetUserComment(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> resp;
    bool isValid = resp.Unmarshalling(reply);
    ASSERT_EQ(isValid, true);
    int32_t changedRows = resp.GetErrCode();
    EXPECT_EQ(changedRows, 1); // 修改了1行

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    using namespace RdbDataShareAdapter;
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, PhotoColumn::PHOTOS_TABLE);
    std::vector<std::string> columns { PhotoColumn::PHOTO_USER_COMMENT };

    shared_ptr<NativeRdb::ResultSet> resSet = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
    EXPECT_NE(resSet, nullptr);
    EXPECT_EQ(resSet->GoToNextRow(), NativeRdb::E_OK);
    int commentIdx = -1;
    resSet->GetColumnIndex(PhotoColumn::PHOTO_USER_COMMENT, commentIdx);
    std::string comment;
    resSet->GetString(commentIdx, comment);
    EXPECT_EQ(comment, userComment);

    ASSERT_EQ(QueryTransCodeInfoByID(fileId, resultSet), 0);
    EXPECT_EQ(GetInt64Val(PhotoColumn::PHOTO_TRANSCODE_TIME, resultSet), 0);
    EXPECT_EQ(GetInt64Val(PhotoColumn::PHOTO_TRANS_CODE_FILE_SIZE, resultSet), 0);
    EXPECT_EQ(GetInt32Val(PhotoColumn::PHOTO_EXIST_COMPATIBLE_DUPLICATE, resultSet), 0);

    system("rm -rf /storage/cloud/files/Photo/665/test.heic");
    system("rm -rf /storage/cloud/files/.editData/Photo/665/test.heic/transcode.jpg");
}
}  // namespace OHOS::Media