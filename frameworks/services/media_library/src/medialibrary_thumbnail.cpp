/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "medialibrary_thumbnail.h"

#include <fcntl.h>

#include "hitrace_meter.h"
#include "distributed_kv_data_manager.h"
#include "image_packer.h"
#include "media_data_ability_const.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "medialibrary_sync_table.h"
#include "medialibrary_sync_table.h"
#include "openssl/sha.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "uri_helper.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const string THUMBNAIL_END_SUFFIX = "_THU";
static const string THUMBNAIL_LCD_END_SUFFIX = "_LCD";
static const string FILE_URI_PREX = "file://";

static const string THUMBNAIL_FORMAT = "image/jpeg";
static constexpr uint8_t THUMBNAIL_QUALITY = 80;
static constexpr uint32_t THUMBNAIL_QUERY_MAX = 1000;
static constexpr int64_t AV_FRAME_TIME = 0;

static constexpr uint8_t NUM_0 = 0;
static constexpr uint8_t NUM_1 = 1;
static constexpr uint8_t NUM_2 = 2;
static constexpr uint8_t NUM_3 = 3;
static constexpr uint8_t NUM_4 = 4;

void ThumbnailDataCopy(ThumbnailData &data, ThumbnailRdbData &rdbData)
{
    data.id = rdbData.id;
    data.path = rdbData.path;
    data.thumbnailKey = rdbData.thumbnailKey;
    data.lcdKey = rdbData.lcdKey;
    data.mediaType = rdbData.mediaType;
}

MediaLibraryThumbnail::MediaLibraryThumbnail()
{
    InitKvStore();
}

void ParseStringResult(shared_ptr<ResultSet> resultSet,
                       int index, string &data, int &errorCode)
{
    bool isNull = true;
    errorCode = resultSet->IsColumnNull(index, isNull);
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed to check column %{private}d null %{private}d", index, errorCode);
    }

    if (!isNull) {
        errorCode = resultSet->GetString(index, data);
        if (errorCode != E_OK) {
            MEDIA_ERR_LOG("Failed to get column %{private}d string %{private}d", index, errorCode);
        }
    } else {
        MEDIA_INFO_LOG("Get column %{private}d null", index);
    }
}

void ParseQueryResult(shared_ptr<ResultSet> resultSet,
                      ThumbnailRdbData &data, int &errorCode)
{
    ParseStringResult(resultSet, NUM_0, data.id, errorCode);
    ParseStringResult(resultSet, NUM_1, data.path, errorCode);
    ParseStringResult(resultSet, NUM_2, data.thumbnailKey, errorCode);
    ParseStringResult(resultSet, NUM_3, data.lcdKey, errorCode);
    data.mediaType = MediaType::MEDIA_TYPE_DEFAULT;
    errorCode = resultSet->GetInt(NUM_4, data.mediaType);
}

bool MediaLibraryThumbnail::CreateThumbnail(ThumbRdbOpt &opts,
                                            ThumbnailData &data,
                                            std::string &outKey)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnail3 IN");
    int errorCode;

    if (!data.thumbnailKey.empty() &&
        IsImageExist(data.thumbnailKey)) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnail image has exist in kvStore");
        return true;
    }

    if (!LoadSourceImage(data)) {
        return false;
    }

    if (!GenThumbnailKey(data)) {
        return false;
    }

    if (data.thumbnailKey.empty()) {
        MEDIA_ERR_LOG("MediaLibraryThumbnail::Gen Thumbnail Key is empty");
        return false;
    }

    if (IsImageExist(data.thumbnailKey)) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnail Get thumbnail in kvStore");
    } else {
        if (!CreateThumbnailData(data)) {
            return false;
        }

        if (SaveThumbnailData(data) != Status::SUCCESS) {
            return false;
        }
    }

    data.lcdKey.clear();

    if (!UpdateThumbnailInfo(opts, data, errorCode)) {
        return false;
    }
    outKey = data.thumbnailKey;

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnail3 OUT");
    return true;
}

bool MediaLibraryThumbnail::CreateThumbnail(ThumbRdbOpt &opts, string &key)
{
    StartTrace(HITRACE_TAG_OHOS, "CreateThumbnail");
    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnail IN");

    ThumbnailData thumbnailData;
    int errorCode;
    shared_ptr<AbsSharedResultSet> queryResultSet;
    queryResultSet = QueryThumbnailInfo(opts, thumbnailData, errorCode);
    if (queryResultSet == nullptr) {
        return false;
    }

    bool ret = CreateThumbnail(opts, thumbnailData, key);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnail OUT");
    FinishTrace(HITRACE_TAG_OHOS);

    return ret;
}

bool MediaLibraryThumbnail::CreateLcd(ThumbRdbOpt &opts, string &key)
{
    StartTrace(HITRACE_TAG_OHOS, "CreateLcd");
    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateLcd IN");

    ThumbnailData thumbnailData;
    int errorCode;
    shared_ptr<AbsSharedResultSet> queryResultSet;
    queryResultSet = QueryThumbnailInfo(opts, thumbnailData, errorCode);
    if (queryResultSet == nullptr) {
        return false;
    }
    bool ret = CreateLcd(opts, thumbnailData, key);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateLcd OUT");
    return ret;
}

bool MediaLibraryThumbnail::CreateLcd(ThumbRdbOpt &opts, ThumbnailData &thumbnailData, string &outKey)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateLcd IN");
    if (!thumbnailData.lcdKey.empty() &&
        IsImageExist(thumbnailData.lcdKey)) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateLcd image has exist in kvStore");
        return true;
    }

    if (!LoadSourceImage(thumbnailData)) {
        return false;
    }

    StartTrace(HITRACE_TAG_OHOS, "CreateLcd GenLcdKey");
    if (!GenLcdKey(thumbnailData)) {
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    if (thumbnailData.lcdKey.empty()) {
        MEDIA_ERR_LOG("MediaLibraryThumbnail::Gen lcd Key is empty");
        return false;
    }

    if (IsImageExist(thumbnailData.lcdKey)) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnail Get lcd in kvStore");
    } else {
        if (!CreateLcdData(thumbnailData)) {
            return false;
        }

        if (SaveLcdData(thumbnailData) != Status::SUCCESS) {
            return false;
        }
    }

    if (thumbnailData.thumbnailKey.empty()) {
        CreateThumbnail(opts, thumbnailData, outKey);
    }

    thumbnailData.thumbnail.clear();

    StartTrace(HITRACE_TAG_OHOS, "CreateLcd UpdateThumbnailInfo");
    int errorCode;
    if (!UpdateThumbnailInfo(opts, thumbnailData, errorCode)) {
        MEDIA_INFO_LOG("UpdateThumbnailInfo faild errorCode : %{private}d", errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    outKey = thumbnailData.lcdKey;

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateLcd OUT");
    FinishTrace(HITRACE_TAG_OHOS);

    return true;
}

shared_ptr<AbsSharedResultSet> MediaLibraryThumbnail::GetThumbnailKey(ThumbRdbOpt &opts, Size &size)
{
    shared_ptr<AbsSharedResultSet> queryResultSet;
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GetThumbnailKey IN");
    if (singleKvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("KvStore is not init");
        return nullptr;
    }

    ThumbnailData thumbnailData;
    int errorCode;
    queryResultSet = QueryThumbnailInfo(opts, thumbnailData, errorCode);
    if (queryResultSet == nullptr) {
        return queryResultSet;
    }

    // Distribute data
    if (MEDIALIBRARY_TABLE.compare(opts.table) != 0) {
        return queryResultSet;
    }

    bool isFromLcd = isThumbnailFromLcd(size);
    if (isFromLcd) {
        if (thumbnailData.lcdKey.empty()) {
            CreateLcd(opts, thumbnailData, thumbnailData.lcdKey);
        } else {
            return queryResultSet;
        }
    } else {
        if (thumbnailData.thumbnailKey.empty()) {
            CreateThumbnail(opts, thumbnailData, thumbnailData.thumbnailKey);
        } else {
            return queryResultSet;
        }
    }

    queryResultSet = QueryThumbnailSet(opts);
    return queryResultSet;
}

unique_ptr<PixelMap> MediaLibraryThumbnail::GetThumbnailByRdb(ThumbRdbOpt &opts,
                                                              Size &size, const std::string &uri)
{
    int errorCode;
    shared_ptr<AbsSharedResultSet> resultSet = GetThumbnailKey(opts, size);
    ThumbnailRdbData rdbData;
    ParseQueryResult(resultSet, rdbData, errorCode);

    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed GetThumbnailKey errorCode : %{private}d", errorCode);
        return nullptr;
    }

    string key = rdbData.thumbnailKey;
    if (isThumbnailFromLcd(size)) {
        key = rdbData.lcdKey;
    }
    if (key.empty()) {
        return nullptr;
    }
    return GetThumbnail(key, size, uri);
}

void MediaLibraryThumbnail::CreateThumbnails(ThumbRdbOpt &opts)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnails IN");
    vector<ThumbnailRdbData> infos;
    int errorCode = -1;
    if (!QueryThumbnailInfos(opts, infos, errorCode)) {
        MEDIA_ERR_LOG("Failed to QueryThumbnailInfos %{private}d", errorCode);
        return;
    }

    if (infos.empty()) {
        MEDIA_ERR_LOG("Infos is empty");
        return;
    }

    for (uint32_t i = 0; i < infos.size(); i++) {
        string key;
        ThumbnailData data;
        opts.row = infos[i].id;
        ThumbnailDataCopy(data, infos[i]);
        CreateThumbnail(opts, data, key);
    }

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnails OUT");
}

bool MediaLibraryThumbnail::LoadAudioFile(string &path,
                                          shared_ptr<PixelMap> &pixelMap)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadAudioFile IN");
#ifdef OLD_MEDIA_STD_API
    MEDIA_ERR_LOG("Audio FetchArtPicture API is not ready!");
    return false;
#else
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    int32_t errorCode = SetSource(avMetadataHelper, path);
    if (errorCode != 0) {
        MEDIA_ERR_LOG("Av meta data helper set source failed %{private}d", errorCode);
        return false;
    }

    auto audioPicMemory = avMetadataHelper->FetchArtPicture();
    if (audioPicMemory == nullptr) {
        MEDIA_ERR_LOG("FetchArtPicture failed!");
        return false;
    }

    SourceOptions opts;
    uint32_t error = SUCCESS;
    unique_ptr<ImageSource> audioImageSource = ImageSource::CreateImageSource(audioPicMemory->GetBase(),
                                                                              audioPicMemory->GetSize(),
                                                                              opts, error);
    if (audioImageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to create image source! %{private}d", error);
        return false;
    }

    error = SUCCESS;
    DecodeOptions decOpts;
    pixelMap = audioImageSource->CreatePixelMap(decOpts, error);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("Av meta data helper fetch frame at time failed");
        return false;
    }
    if (pixelMap->GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        pixelMap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    }
#endif
    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadAudioFile OUT");
    return true;
}
bool MediaLibraryThumbnail::LoadVideoFile(string &path,
                                          shared_ptr<PixelMap> &pixelMap)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadVideoFile IN");
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    int32_t errorCode = SetSource(avMetadataHelper, path);
    if (errorCode != 0) {
        MEDIA_ERR_LOG("Av meta data helper set source failed %{private}d", errorCode);
        return false;
    }
    PixelMapParams param;
    param.colorFormat = PixelFormat::RGBA_8888;
    pixelMap = avMetadataHelper->FetchFrameAtTime(AV_FRAME_TIME,
                                                  AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC,
                                                  param);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("Av meta data helper fetch frame at time failed");
        return false;
    }
    if (pixelMap->GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        pixelMap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    }
    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadVideoFile OUT");
    return true;
}
bool MediaLibraryThumbnail::LoadImageFile(string &path,
                                          shared_ptr<PixelMap> &pixelMap)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadImageFile IN");
    uint32_t errorCode = 0;
    SourceOptions opts;

    StartTrace(HITRACE_TAG_OHOS, "ImageSource::CreateImageSource");
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path,
                                                                         opts,
                                                                         errorCode);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create image source path %{private}s err %{private}d",
                      path.c_str(), errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    StartTrace(HITRACE_TAG_OHOS, "imageSource->CreatePixelMap");
    DecodeOptions decodeOpts;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create pixelmap path %{private}s err %{private}d",
                      path.c_str(), errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadImageFile OUT");
    return true;
}

bool MediaLibraryThumbnail::GenKey(vector<uint8_t> &data, string &key)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GenKey IN");
    if (data.size() <= 0) {
        MEDIA_ERR_LOG("Empty data");
        return false;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);
    // here we translate sha256 hash to hexadecimal. each 8-bit char will be presented by two characters([0-9a-f])
    constexpr int CHAR_WIDTH = 8;
    constexpr int HEX_WIDTH = 4;
    constexpr unsigned char HEX_MASK = 0xf;
    constexpr int HEX_A = 10;
    key.reserve(SHA256_DIGEST_LENGTH * (CHAR_WIDTH / HEX_WIDTH));
    for (unsigned char i : hash) {
        unsigned char hex = i >> HEX_WIDTH;
        if (hex < HEX_A) {
            key.push_back('0' + hex);
        } else {
            key.push_back('a' + hex - HEX_A);
        }
        hex = i & HEX_MASK;
        if (hex < HEX_A) {
            key.push_back('0' + hex);
        } else {
            key.push_back('a' + hex - HEX_A);
        }
    }
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GenKey OUT [%{private}s]", key.c_str());
    return true;
}

bool MediaLibraryThumbnail::CompressImage(std::shared_ptr<PixelMap> &pixelMap,
                                          Size &size,
                                          std::vector<uint8_t> &data)
{
    StartTrace(HITRACE_TAG_OHOS, "CompressImage");

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CompressImage IN");
    InitializationOptions opts = {
        .size = size,
        .pixelFormat = PixelFormat::BGRA_8888,
        .alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL,
        .scaleMode = ScaleMode::CENTER_CROP
    };

    StartTrace(HITRACE_TAG_OHOS, "PixelMap::Create");
    unique_ptr<PixelMap> compressImage = PixelMap::Create(*pixelMap, opts);
    FinishTrace(HITRACE_TAG_OHOS);

    PackOption option = {
        .format = THUMBNAIL_FORMAT,
        .quality = THUMBNAIL_QUALITY,
        .numberHint = NUM_1
    };
    data.resize(compressImage->GetByteCount());

    StartTrace(HITRACE_TAG_OHOS, "imagePacker.StartPacking");
    ImagePacker imagePacker;
    uint32_t errorCode = imagePacker.StartPacking(data.data(), data.size(), option);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    StartTrace(HITRACE_TAG_OHOS, "imagePacker.AddImage");
    errorCode = imagePacker.AddImage(*compressImage);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    StartTrace(HITRACE_TAG_OHOS, "imagePacker.FinalizePacking");
    int64_t packedSize = 0;
    errorCode = imagePacker.FinalizePacking(packedSize);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to StartPacking %{private}d", errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    MEDIA_INFO_LOG("packedSize=%{private}lld.", static_cast<long long>(packedSize));
    data.resize(packedSize);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CompressImage OUT");
    FinishTrace(HITRACE_TAG_OHOS);

    return true;
}

Status MediaLibraryThumbnail::SaveImage(string &key, vector<uint8_t> &image)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SaveImage IN");
    Status status = Status::ERROR;
    if (singleKvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("KvStore is not init");
        return status;
    }

    StartTrace(HITRACE_TAG_OHOS, "SaveImage singleKvStorePtr_->Put");
    Value val(image);
    status = singleKvStorePtr_->Put(key, val);
    FinishTrace(HITRACE_TAG_OHOS);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::SaveImage OUT");
    return status;
}

shared_ptr<AbsSharedResultSet> MediaLibraryThumbnail::QueryThumbnailSet(ThumbRdbOpt &opts)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::QueryThumbnailSet IN row [%{private}s]",
                   opts.row.c_str());
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE
    };

    vector<string> selectionArgs;
    string strQueryCondition = MEDIA_DATA_DB_ID + "=" + opts.row;

    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.SetWhereClause(strQueryCondition);
    rdbPredicates.SetWhereArgs(selectionArgs);

    shared_ptr<AbsSharedResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    MEDIA_INFO_LOG("MediaLibraryThumbnail::QueryThumbnailSet OUT");
    return resultSet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryThumbnail::QueryThumbnailInfo(ThumbRdbOpt &opts,
                                                                         ThumbnailData &data, int &errorCode)
{
    StartTrace(HITRACE_TAG_OHOS, "QueryThumbnailInfo");
    shared_ptr<AbsSharedResultSet> resultSet = QueryThumbnailSet(opts);
    int rowCount = 0;
    errorCode = resultSet->GetRowCount(rowCount);
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{private}d", errorCode);
        return nullptr;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    if (rowCount <= 0) {
        MEDIA_ERR_LOG("No match files");
        errorCode = E_EMPTY_VALUES_BUCKET;
        return nullptr;
    }

    errorCode = resultSet->GoToFirstRow();
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{private}d", errorCode);
        return nullptr;
    }

    int columnCount = 0;
    errorCode = resultSet->GetColumnCount(columnCount);
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed to get column count %{private}d", errorCode);
        return nullptr;
    }

    if (columnCount <= 0) {
        MEDIA_ERR_LOG("No column!");
        errorCode = E_EMPTY_VALUES_BUCKET;
        return nullptr;
    }

    ThumbnailRdbData rdbData;
    ParseQueryResult(resultSet, rdbData, errorCode);
    ThumbnailDataCopy(data, rdbData);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::QueryThumbnailInfo OUT");
    FinishTrace(HITRACE_TAG_OHOS);

    return resultSet;
}

bool MediaLibraryThumbnail::QueryThumbnailInfos(ThumbRdbOpt &opts,
                                                vector<ThumbnailRdbData> &infos,
                                                int &errorCode)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::QueryThumbnailInfos IN");
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.IsNull(MEDIA_DATA_DB_THUMBNAIL);
    rdbPredicates.Limit(THUMBNAIL_QUERY_MAX);

    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    int rowCount = 0;
    errorCode = resultSet->GetRowCount(rowCount);
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{private}d", errorCode);
        return false;
    }

    if (rowCount <= 0) {
        MEDIA_ERR_LOG("No match! %{private}s", rdbPredicates.ToString().c_str());
        errorCode = E_EMPTY_VALUES_BUCKET;
        return false;
    }

    errorCode = resultSet->GoToFirstRow();
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{private}d", errorCode);
        return false;
    }

    int columnCount = 0;
    errorCode = resultSet->GetColumnCount(columnCount);
    if (errorCode != E_OK) {
        MEDIA_ERR_LOG("Failed to get column count %{private}d", errorCode);
        return false;
    }

    if (columnCount <= 0) {
        MEDIA_ERR_LOG("No column!");
        errorCode = E_EMPTY_VALUES_BUCKET;
        return false;
    }

    do {
        ThumbnailRdbData data;
        ParseQueryResult(resultSet, data, errorCode);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);

    resultSet.reset();

    MEDIA_INFO_LOG("MediaLibraryThumbnail::QueryThumbnailInfos OUT");
    return true;
}

bool MediaLibraryThumbnail::UpdateThumbnailInfo(ThumbRdbOpt &opts,
                                                ThumbnailData &data,
                                                int &errorCode)
{
    MEDIA_DEBUG_LOG("MediaLibraryThumbnail::UpdateThumbnailInfo IN");
    ValuesBucket values;
    int changedRows;
    if (data.thumbnailKey.empty() && data.lcdKey.empty()) {
        MEDIA_ERR_LOG("No key to update!");
        return false;
    }

    if (data.thumbnailKey.length() > 0) {
        values.PutString(MEDIA_DATA_DB_THUMBNAIL, data.thumbnailKey);
    }

    if (data.lcdKey.length() > 0) {
        values.PutString(MEDIA_DATA_DB_LCD, data.lcdKey);
    }

    StartTrace(HITRACE_TAG_OHOS, "UpdateThumbnailInfo opts.store->Update");
    errorCode = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID+" = ?",
        vector<string> { opts.row });
    if (errorCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{private}d", errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    std::vector<std::string> devices = std::vector<std::string>();
    MediaLibrarySyncTable syncTable;
    syncTable.SyncPushTable(opts.store, BUNDLE_NAME, MEDIALIBRARY_TABLE, devices);

    return true;
}

bool MediaLibraryThumbnail::LoadSourceImage(ThumbnailData &data)
{
    StartTrace(HITRACE_TAG_OHOS, "LoadSourceImage");
    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadSourceImage IN");

    bool ret = false;
    if (data.mediaType == MEDIA_TYPE_VIDEO) {
        ret = LoadVideoFile(data.path, data.source);
    } else if (data.mediaType == MEDIA_TYPE_AUDIO) {
        ret = LoadAudioFile(data.path, data.source);
    } else {
        ret = LoadImageFile(data.path, data.source);
    }

    MEDIA_INFO_LOG("MediaLibraryThumbnail::LoadSourceImage OUT");
    FinishTrace(HITRACE_TAG_OHOS);

    return ret;
}
bool MediaLibraryThumbnail::GenThumbnailKey(ThumbnailData &data)
{
    StartTrace(HITRACE_TAG_OHOS, "GenThumbnailKey");
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GenThumbnailKey IN");
    vector<uint8_t> source(data.source->GetPixels(),
        data.source->GetPixels() + data.source->GetByteCount());

    bool ret = GenKey(source, data.thumbnailKey);
    if (ret) {
        data.thumbnailKey += THUMBNAIL_END_SUFFIX;
    }

    MEDIA_INFO_LOG("MediaLibraryThumbnail::GenThumbnailKey OUT [%{private}s]",
                   data.thumbnailKey.c_str());
    FinishTrace(HITRACE_TAG_OHOS);

    return ret;
}
bool MediaLibraryThumbnail::GenLcdKey(ThumbnailData &data)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GenLcdKey IN");
    vector<uint8_t> source(data.source->GetPixels(),
        data.source->GetPixels() + data.source->GetByteCount());

    bool ret = GenKey(source, data.lcdKey);
    if (ret) {
        data.lcdKey += THUMBNAIL_LCD_END_SUFFIX;
    }
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GenLcdKey OUT");
    return ret;
}
bool MediaLibraryThumbnail::CreateThumbnailData(ThumbnailData &data)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnailData IN");

    Size size = {
        .width = DEFAULT_THUMBNAIL_SIZE.width,
        .height = DEFAULT_THUMBNAIL_SIZE.height
    };

    bool ret = CompressImage(data.source, size, data.thumbnail);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateThumbnailData OUT");
    return ret;
}

bool MediaLibraryThumbnail::CreateLcdData(ThumbnailData &data)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateLcdData IN");

    Size size = DEFAULT_LCD_SIZE;
    double widthF = data.source->GetWidth();
    widthF = widthF*size.height/data.source->GetHeight();
    size.width = static_cast<int32_t>(widthF);

    bool ret = CompressImage(data.source, size, data.lcd);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::CreateLcdData OUT");
    return ret;
}

Status MediaLibraryThumbnail::SaveThumbnailData(ThumbnailData &data)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SaveThumbnailData IN");

    Status status = SaveImage(data.thumbnailKey, data.thumbnail);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::SaveThumbnailData OUT");
    return status;
}
Status MediaLibraryThumbnail::SaveLcdData(ThumbnailData &data)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SaveLcdData IN");

    Status status = SaveImage(data.lcdKey, data.lcd);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::SaveLcdData OUT");
    return status;
}
bool MediaLibraryThumbnail::GetThumbnailFromKvStore(ThumbnailData &data)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GetThumbnailFromKvStore IN");

    bool ret = GetImage(data.thumbnailKey, data.thumbnail);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::GetThumbnailFromKvStore OUT");
    return ret;
}
bool MediaLibraryThumbnail::GetLcdFromKvStore(ThumbnailData &data)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::GetLcdFromKvStore IN");

    bool ret = GetImage(data.lcdKey, data.lcd);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::GetLcdFromKvStore OUT");
    return ret;
}

bool MediaLibraryThumbnail::ResizeThumbnailToTarget(ThumbnailData &data,
                                                    Size &size,
                                                    unique_ptr<PixelMap> &pixelMap)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::ResizeThumbnailToTarget IN");

    bool ret = ResizeImage(data.thumbnail, size, pixelMap);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::ResizeThumbnailToTarget OUT");
    return ret;
}

bool MediaLibraryThumbnail::ResizeLcdToTarget(ThumbnailData &data,
                                              Size &size,
                                              unique_ptr<PixelMap> &pixelMap)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::ResizeLcdToTarget IN");

    bool ret = ResizeImage(data.lcd, size, pixelMap);

    MEDIA_INFO_LOG("MediaLibraryThumbnail::ResizeLcdToTarget OUT");
    return ret;
}
int32_t MediaLibraryThumbnail::SetSource(std::shared_ptr<AVMetadataHelper> avMetadataHelper, const std::string &path)
{
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource IN");
    if (avMetadataHelper == nullptr) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource avMetadataHelper == nullptr");
        return -1;
    }
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource path = %{private}s", path.c_str());
    UriHelper uriHelper(path);
    if (uriHelper.UriType() != UriHelper::URI_TYPE_FILE && !uriHelper.AccessCheck(UriHelper::URI_READ)) {
        std::cout << "Invalid file Path" << std::endl;
        return -1;
    }
    std::string rawFile = uriHelper.FormattedUri();
    rawFile = rawFile.substr(strlen("file://"));
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource rawFile = %{private}s", rawFile.c_str());
    int32_t fd = open(rawFile.c_str(), O_RDONLY);
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource fd = %{private}d", fd);
    if (fd <= 0) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource Open file failed");
        return -1;
    }

    struct stat64 st;
    if (fstat64(fd, &st) != 0) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource Get file state failed");
        (void)close(fd);
        return -1;
    }
    int64_t length = static_cast<int64_t>(st.st_size);
    int32_t ret = avMetadataHelper->SetSource(fd, 0, length, 1);
    if (ret != 0) {
        MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource fail");
        (void)close(fd);
        return -1;
    }
    (void)close(fd);
    MEDIA_INFO_LOG("MediaLibraryThumbnail::SetSource OUT");
    return 0;
}
} // namespace Media
} // namespace OHOS
