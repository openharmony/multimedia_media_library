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

#define MLOG_TAG "MediaAlbumsControllerServiceTest"

#include "change_request_set_album_property_test.h"

#include <memory>
#include <string>

#define private public
#define protected public
#include "media_albums_controller_service.h"
#undef private
#undef protected

#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "create_album_vo.h"
#include "create_asset_vo.h"
#include "change_request_dismiss_vo.h"
#include "change_request_set_album_name_vo.h"
#include "change_request_set_cover_uri_vo.h"
#include "change_request_set_display_level_vo.h"
#include "change_request_set_is_me_vo.h"
#include "media_assets_controller_service.h"
#include "set_subtitle_vo.h"
#include "set_highlight_user_action_data_vo.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace IPC;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;

static int32_t ClearUserAlbums()
{
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::USER));

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear album table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void ChangeRequestSetAlbumPropertyTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearUserAlbums();
    MEDIA_INFO_LOG("SetUpTestCase");
}

void ChangeRequestSetAlbumPropertyTest::TearDownTestCase(void)
{
    ClearUserAlbums();
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void ChangeRequestSetAlbumPropertyTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void ChangeRequestSetAlbumPropertyTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static int32_t ServiceCreateAlbum(const std::string &albumName)
{
    CreateAlbumReqBody reqBody;
    reqBody.albumName = albumName;

    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->CreatePhotoAlbum(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }

    return respVo.GetErrCode();
}

static int32_t ServicePublicCreateAsset(const std::string &ext, const std::string &title = "")
{
    CreateAssetReqBody reqBody;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.title = title;
    reqBody.extension = ext;

    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->PublicCreateAsset(data, reply);

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

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_001");
    int32_t albumId = ServiceCreateAlbum("Album_Test_001");
    ASSERT_GT(albumId, 0);
    int32_t fileId = ServicePublicCreateAsset("jpg");
    ASSERT_GT(fileId, 0);
    string coverUri = "file://media/Photo/" + to_string(fileId);
    ChangeRequestSetCoverUriReqBody reqBody;
    reqBody.albumId = to_string(albumId);
    reqBody.coverUri = coverUri;
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::USER);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::USER_GENERIC);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestSetCoverUri(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    ChangeRequestSetAlbumNameReqBody setAlbumNameReqBody;
    setAlbumNameReqBody.albumId = reqBody.albumId;
    setAlbumNameReqBody.albumName = "hello";
    setAlbumNameReqBody.albumType = reqBody.albumType;
    setAlbumNameReqBody.albumSubType = reqBody.albumSubType;
    result = setAlbumNameReqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestSetAlbumName(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, 1);
    MEDIA_INFO_LOG("End SetAlbumProperty_Test_001");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_002");
    ChangeRequestSetCoverUriReqBody reqBody;
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::USER);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::HIDDEN);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestSetCoverUri(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);

    ChangeRequestSetAlbumNameReqBody setAlbumNameReqBody;
    setAlbumNameReqBody.albumType = reqBody.albumType;
    setAlbumNameReqBody.albumSubType = reqBody.albumSubType;
    result = setAlbumNameReqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestSetAlbumName(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);
    MEDIA_INFO_LOG("End SetAlbumProperty_Test_002");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_003");
    int32_t albumId = ServiceCreateAlbum("Album_Test_001");
    ASSERT_GT(albumId, 0);
    int32_t fileId = ServicePublicCreateAsset("jpg");
    ASSERT_GT(fileId, 0);
    string coverUri = "file://media/Photo/" + to_string(fileId);
    ChangeRequestSetCoverUriReqBody reqBody;
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestSetCoverUri(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_NE(errCode, E_OK);

    ChangeRequestSetAlbumNameReqBody setAlbumNameReqBody;
    setAlbumNameReqBody.albumType = reqBody.albumType;
    setAlbumNameReqBody.albumSubType = reqBody.albumSubType;
    setAlbumNameReqBody.albumName = "hello";
    setAlbumNameReqBody.albumId = to_string(albumId);
    result = setAlbumNameReqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestSetAlbumName(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_OK);
    MEDIA_INFO_LOG("End SetAlbumProperty_Test_003");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_004");
    string albumId = "3";
    string coverUri = "file://media/Photo/3";
    ChangeRequestSetCoverUriReqBody reqBody;
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::GROUP_PHOTO);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestSetCoverUri(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_NE(errCode, E_OK);

    ChangeRequestSetAlbumNameReqBody setAlbumNameReqBody;
    setAlbumNameReqBody.albumType = reqBody.albumType;
    setAlbumNameReqBody.albumSubType = reqBody.albumSubType;
    setAlbumNameReqBody.albumName = "hello";
    setAlbumNameReqBody.albumId = albumId;
    result = setAlbumNameReqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestSetAlbumName(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_OK);
    MEDIA_INFO_LOG("End SetAlbumProperty_Test_004");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_005");
    string albumId = "4";
    string coverUri = "file://media/Photo/4";
    ChangeRequestSetCoverUriReqBody reqBody;
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestSetCoverUri(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_NE(errCode, E_OK);

    ChangeRequestSetAlbumNameReqBody setAlbumNameReqBody;
    setAlbumNameReqBody.albumType = reqBody.albumType;
    setAlbumNameReqBody.albumSubType = reqBody.albumSubType;
    setAlbumNameReqBody.albumName = "hello";
    setAlbumNameReqBody.albumId = albumId;
    result = setAlbumNameReqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestSetAlbumName(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_OK);
    MEDIA_INFO_LOG("End SetAlbumProperty_Test_005");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_006");
    ChangeRequestSetIsMeReqBody reqBody;
    reqBody.albumId = "1";
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestSetIsMe(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);
    reqBody.isMe = 1;
    result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestSetIsMe(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_NE(errCode, E_OK);
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_006");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_007");
    ChangeRequestSetDisplayLevelReqBody reqBody;
    reqBody.albumId = "1";
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestSetDisplayLevel(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);
    reqBody.displayLevel = 2;
    result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestSetDisplayLevel(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);

    MEDIA_INFO_LOG("End SetAlbumProperty_Test_007");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_008");
    ChangeRequesDismissReqBody reqBody;
    reqBody.albumId = "1";
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->ChangeRequestDismiss(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);

    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::GROUP_PHOTO);
    result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->ChangeRequestDismiss(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_OK);

    MEDIA_INFO_LOG("End SetAlbumProperty_Test_008");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_009");
    SetHighlightUserActionDataReqBody reqBody;
    reqBody.albumId = "1";
    reqBody.userActionType = static_cast<int32_t>(HighlightUserActionType::INVALID_USER_ACTION);
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->SetHighlightUserActionData(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);

    reqBody.userActionType = static_cast<int32_t>(HighlightUserActionType::INSERTED_PIC_COUNT);
    result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->SetHighlightUserActionData(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);

    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);

    MEDIA_INFO_LOG("End SetAlbumProperty_Test_009");
}

HWTEST_F(ChangeRequestSetAlbumPropertyTest, SetAlbumProperty_Test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SetAlbumProperty_Test_010");
    SetSubtitleReqBody reqBody;
    reqBody.albumId = "1";
    reqBody.albumType = static_cast<int32_t>(PhotoAlbumType::SMART);
    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT);

    MessageParcel data;
    bool result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->SetSubtitle(data, reply);

    IPC::MediaRespVo<MediaEmptyObjVo> respVo;
    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    int32_t errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_INVALID_VALUES);

    reqBody.albumSubType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);
    result = reqBody.Marshalling(data);
    ASSERT_NE(result, false);
    service->SetSubtitle(data, reply);

    result = respVo.Unmarshalling(reply);
    ASSERT_NE(result, false);

    errCode = respVo.GetErrCode();
    EXPECT_EQ(errCode, E_OK);

    MEDIA_INFO_LOG("End SetAlbumProperty_Test_010");
}
}  // namespace OHOS::Media