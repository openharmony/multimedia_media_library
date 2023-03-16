/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Thumbnail"

#include "thumbnail_utils.h"

#include <fcntl.h>
#include <sys/stat.h>
#include "datashare_abs_result_set.h"
#include "device_manager.h"
#include "distributed_kv_data_manager.h"
#include "hitrace_meter.h"
#include "image_packer.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "parameter.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "thumbnail_const.h"
#include "uri_helper.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
bool ThumbnailUtils::UpdateRemotePath(string &path, const string &networkId)
{
    MEDIA_DEBUG_LOG("ThumbnailUtils::UpdateRemotePath IN path = %{private}s, networkId = %{private}s",
        path.c_str(), networkId.c_str());
    if (path.empty() || networkId.empty()) {
        return false;
    }

    size_t pos = path.find(MEDIA_DATA_DEVICE_PATH);
    if (pos == string::npos) {
        return false;
    }

    path.replace(pos, MEDIA_DATA_DEVICE_PATH.size(), networkId);
    return true;
}

bool ThumbnailUtils::DeleteLcdData(ThumbRdbOpt &opts, ThumbnailData &thumbnailData)
{
    if (thumbnailData.lcdKey.empty()) {
        MEDIA_ERR_LOG("lcd Key is empty");
        return false;
    }

    if (IsImageExist(thumbnailData.lcdKey, opts.networkId, opts.kvStore)) {
        if (!RemoveDataFromKv(opts.kvStore, thumbnailData.lcdKey)) {
            MEDIA_ERR_LOG("ThumbnailUtils::RemoveDataFromKv faild");
            return false;
        }
        if (!CleanThumbnailInfo(opts, false, true)) {
            return false;
        }
    }

    return true;
}

bool ThumbnailUtils::DeleteDistributeLcdData(ThumbRdbOpt &opts, ThumbnailData &thumbnailData)
{
    if (thumbnailData.lcdKey.empty()) {
        MEDIA_ERR_LOG("lcd Key is empty");
        return false;
    }

    if (IsImageExist(thumbnailData.lcdKey, opts.networkId, opts.kvStore)) {
        if (!RemoveDataFromKv(opts.kvStore, thumbnailData.lcdKey)) {
            MEDIA_ERR_LOG("ThumbnailUtils::RemoveDataFromKv faild");
            return false;
        }
        if (!CleanDistributeLcdInfo(opts)) {
            return false;
        }
    }

    return true;
}

bool ThumbnailUtils::ClearThumbnailAllRecord(ThumbRdbOpt &opts, ThumbnailData &thumbnailData)
{
    if (IsImageExist(thumbnailData.lcdKey, opts.networkId, opts.kvStore)) {
        if (!RemoveDataFromKv(opts.kvStore, thumbnailData.lcdKey)) {
            MEDIA_ERR_LOG("ThumbnailUtils::RemoveDataFromKv faild");
            return false;
        }
    }

    if (IsImageExist(thumbnailData.thumbnailKey, opts.networkId, opts.kvStore)) {
        if (!RemoveDataFromKv(opts.kvStore, thumbnailData.thumbnailKey)) {
            MEDIA_ERR_LOG("ThumbnailUtils::RemoveDataFromKv faild");
            return false;
        }
    }

    if (!DeleteDistributeThumbnailInfo(opts)) {
        return false;
    }
    return true;
}

bool ThumbnailUtils::LoadAudioFile(const string &path, shared_ptr<PixelMap> &pixelMap, float &degrees)
{
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    int32_t err = SetSource(avMetadataHelper, path);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Av meta data helper set source failed %{public}d", err);
        return false;
    }

    auto audioPicMemory = avMetadataHelper->FetchArtPicture();
    if (audioPicMemory == nullptr) {
        MEDIA_ERR_LOG("FetchArtPicture failed!");
        return false;
    }

    SourceOptions opts;
    uint32_t errCode = 0;
    unique_ptr<ImageSource> audioImageSource = ImageSource::CreateImageSource(audioPicMemory->GetBase(),
        audioPicMemory->GetSize(), opts, errCode);
    if (audioImageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to create image source! path %{private}s errCode %{public}d",
            path.c_str(), errCode);
        return false;
    }

    errCode = 0;
    DecodeOptions decOpts;
    pixelMap = audioImageSource->CreatePixelMap(decOpts, errCode);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("Av meta data helper fetch frame at time failed");
        return false;
    }
    if (pixelMap->GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        pixelMap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    }
    degrees = 0.0;
    return true;
}

bool ThumbnailUtils::LoadVideoFile(const string &path, shared_ptr<PixelMap> &pixelMap, float &degrees)
{
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    int32_t err = SetSource(avMetadataHelper, path);
    if (err != 0) {
        MEDIA_ERR_LOG("Av meta data helper set source failed path %{private}s err %{public}d",
            path.c_str(), err);
        return false;
    }
    PixelMapParams param;
    param.colorFormat = PixelFormat::RGBA_8888;
    pixelMap = avMetadataHelper->FetchFrameAtTime(AV_FRAME_TIME,
        AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC, param);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("Av meta data helper fetch frame at time failed");
        return false;
    }
    if (pixelMap->GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        pixelMap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    }
    std::string metaData = avMetadataHelper->ResolveMetadata(AV_KEY_VIDEO_ORIENTATION);
    if (metaData == "") {
        degrees = 0.0;
    } else {
        std::istringstream iss(metaData);
        iss >> degrees;
    }
    return true;
}

bool ThumbnailUtils::LoadImageFile(const string &path, shared_ptr<PixelMap> &pixelMap, float &degrees)
{
    uint32_t err = 0;
    SourceOptions opts;

    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::CreateImageSource");
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, err);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to create image source path %{private}s err %{public}d",
            path.c_str(), err);
        return false;
    }
    tracer.Finish();
    tracer.Start("imageSource->CreatePixelMap");

    DecodeOptions decodeOpts;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to create pixelmap path %{private}s err %{public}d",
            path.c_str(), err);
        return false;
    }
    int intTempMeta;
    err = imageSource->GetImagePropertyInt(0, MEDIA_DATA_IMAGE_ORIENTATION, intTempMeta);
    if (err != SUCCESS) {
        degrees = 0.0;
    } else {
        degrees = static_cast<float>(intTempMeta);
    }
    return true;
}

std::string ThumbnailUtils::GetUdid()
{
    static std::string innerUdid;

    if (!innerUdid.empty()) {
        return innerUdid;
    }

    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto ret = deviceManager.GetLocalDeviceInfo(BUNDLE_NAME, deviceInfo);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("get local device info failed, ret %{public}d", ret);
        return std::string();
    }

    ret = deviceManager.GetUdidByNetworkId(BUNDLE_NAME, deviceInfo.networkId, innerUdid);
    if (ret != 0) {
        MEDIA_ERR_LOG("GetDeviceUdid error networkId = %{private}s, ret %{public}d",
            deviceInfo.networkId, ret);
        return std::string();
    }
    return innerUdid;
}

bool ThumbnailUtils::GenKey(ThumbnailData &data, std::string &key)
{
    MediaLibraryTracer tracer;
    tracer.Start("GenerateKey");
    if (data.hashKey.empty()) {
        std::string sourceKey = GetUdid() + data.path + to_string(data.dateModified);
        MEDIA_DEBUG_LOG("ThumbnailUtils::GenKey sourceKey %{private}s", sourceKey.c_str());
        int32_t ret = MediaLibraryCommonUtils::GenKeySHA256(sourceKey, data.hashKey);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("MediaLibraryThumbnail::Failed to GenKey, err: %{public}d", ret);
            return false;
        }
    }
    key = data.hashKey + data.suffix;

    MEDIA_DEBUG_LOG("GenKey OUT [%{public}s]", key.c_str());
    return true;
}

bool ThumbnailUtils::GenThumbnailKey(ThumbnailData &data)
{
    data.suffix = THUMBNAIL_END_SUFFIX;
    return GenKey(data, data.thumbnailKey);
}

bool ThumbnailUtils::GenLcdKey(ThumbnailData &data)
{
    data.suffix = THUMBNAIL_LCD_END_SUFFIX;
    return GenKey(data, data.lcdKey);
}


bool ThumbnailUtils::CompressImage(std::shared_ptr<PixelMap> &pixelMap, const Size &size,
    std::vector<uint8_t> &data, float degrees)
{
    MediaLibraryTracer tracer;
    tracer.Start("PixelMap::Create");
    InitializationOptions opts = {
        .size = size,
        .pixelFormat = PixelFormat::BGRA_8888,
        .alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL,
        .scaleMode = ScaleMode::CENTER_CROP
    };

    unique_ptr<PixelMap> compressImage = PixelMap::Create(*pixelMap, opts);
    tracer.Finish();
    if (compressImage == nullptr) {
        MEDIA_ERR_LOG("Failed to create compressImage");
        return false;
    }

    PackOption option = {
        .format = THUMBNAIL_FORMAT,
        .quality = THUMBNAIL_QUALITY,
        .numberHint = NUMBER_HINT_1
    };
    compressImage->rotate(degrees);
    data.resize(compressImage->GetByteCount());
    tracer.Start("imagePacker.StartPacking");
    ImagePacker imagePacker;
    uint32_t err = imagePacker.StartPacking(data.data(), data.size(), option);
    tracer.Finish();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to StartPacking %{public}d", err);
        return false;
    }

    tracer.Start("imagePacker.AddImage");
    err = imagePacker.AddImage(*compressImage);
    tracer.Finish();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to StartPacking %{public}d", err);
        return false;
    }

    tracer.Start("imagePacker.FinalizePacking");
    int64_t packedSize = 0;
    err = imagePacker.FinalizePacking(packedSize);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to StartPacking %{public}d", err);
        return false;
    }

    data.resize(packedSize);
    return true;
}

Status ThumbnailUtils::SaveImage(const shared_ptr<SingleKvStore> &kvStore, const string &key,
    const vector<uint8_t> &image)
{
    MEDIA_DEBUG_LOG("ThumbnailUtils::SaveImage IN key [%{public}s]", key.c_str());
    Status status = Status::ERROR;
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("KvStore is not init");
        return status;
    }

    MediaLibraryTracer tracer;
    tracer.Start("SaveImage kvStore->Put");
    Value val(image);
    status = kvStore->Put(key, val);
    return status;
}

shared_ptr<AbsSharedResultSet> ThumbnailUtils::QueryThumbnailSet(ThumbRdbOpt &opts)
{
    MEDIA_DEBUG_LOG("ThumbnailUtils::QueryThumbnailSet IN row [%{public}s]", opts.row.c_str());
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_MODIFIED
    };

    vector<string> selectionArgs;
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + opts.row;

    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.SetWhereClause(strQueryCondition);
    rdbPredicates.SetWhereArgs(selectionArgs);
    shared_ptr<AbsSharedResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    return resultSet;
}

shared_ptr<AbsSharedResultSet> ThumbnailUtils::QueryThumbnailInfo(ThumbRdbOpt &opts,
    ThumbnailData &data, int &err)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnailInfo");
    shared_ptr<AbsSharedResultSet> resultSet = QueryThumbnailSet(opts);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return nullptr;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return nullptr;
    }

    ThumbnailRdbData rdbData;
    ParseQueryResult(resultSet, rdbData, err);
    ThumbnailDataCopy(data, rdbData);
    return resultSet;
}

bool ThumbnailUtils::QueryLcdCount(ThumbRdbOpt &opts, int &outLcdCount, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.IsNotNull(MEDIA_DATA_DB_LCD);
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("query failed");
        return false;
    }
    int rowCount = 0;
    err = resultSet->GetRowCount(rowCount);
    resultSet.reset();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{public}d", err);
        return false;
    }
    MEDIA_DEBUG_LOG("rowCount is %{public}d", rowCount);
    if (rowCount <= 0) {
        MEDIA_INFO_LOG("No match! %{public}s", rdbPredicates.ToString().c_str());
        rowCount = 0;
    }

    outLcdCount = rowCount;
    return true;
}

bool ThumbnailUtils::QueryDistributeLcdCount(ThumbRdbOpt &opts, int &outLcdCount, int &err)
{
    vector<string> column = {
        REMOTE_THUMBNAIL_DB_ID,
    };
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, opts.udid);
    rdbPredicates.IsNotNull(MEDIA_DATA_DB_LCD);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("query failed");
        return false;
    }
    int rowCount = 0;
    err = resultSet->GetRowCount(rowCount);
    resultSet.reset();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{public}d", err);
        return false;
    }
    MEDIA_INFO_LOG("rowCount is %{public}d", rowCount);
    if (rowCount <= 0) {
        MEDIA_INFO_LOG("No match! %{public}s", rdbPredicates.ToString().c_str());
        rowCount = 0;
    }
    outLcdCount = rowCount;
    return true;
}

bool ThumbnailUtils::QueryHasLcdFiles(ThumbRdbOpt &opts, vector<ThumbnailRdbData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_MODIFIED
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.IsNotNull(MEDIA_DATA_DB_LCD);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return false;
    }

    do {
        ThumbnailRdbData data;
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);

    resultSet.reset();
    return true;
}

bool ThumbnailUtils::QueryHasThumbnailFiles(ThumbRdbOpt &opts, vector<ThumbnailRdbData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_MODIFIED
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.IsNotNull(MEDIA_DATA_DB_THUMBNAIL);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return false;
    }

    do {
        ThumbnailRdbData data;
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);

    resultSet.reset();
    return true;
}

bool ThumbnailUtils::QueryAgingDistributeLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
    vector<ThumbnailRdbData> &infos, int &err)
{
    vector<string> column = {
        REMOTE_THUMBNAIL_DB_FILE_ID,
        MEDIA_DATA_DB_LCD
    };
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.IsNotNull(MEDIA_DATA_DB_LCD);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, opts.udid);

    rdbPredicates.Limit(LcdLimit);
    rdbPredicates.OrderByAsc(MEDIA_DATA_DB_TIME_VISIT);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return false;
    }

    do {
        ThumbnailRdbData data;
        ParseQueryResult(resultSet, data, err);
        if (!data.lcdKey.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);

    resultSet.reset();
    return true;
}

bool ThumbnailUtils::QueryAgingLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
    vector<ThumbnailRdbData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_MODIFIED
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.IsNotNull(MEDIA_DATA_DB_LCD);
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));

    rdbPredicates.Limit(LcdLimit);
    rdbPredicates.OrderByAsc(MEDIA_DATA_DB_TIME_VISIT);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return false;
    }

    do {
        ThumbnailRdbData data;
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);

    resultSet.reset();
    return true;
}

bool ThumbnailUtils::QueryNoLcdInfos(ThumbRdbOpt &opts, int LcdLimit, vector<ThumbnailRdbData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_MODIFIED
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.IsNull(MEDIA_DATA_DB_LCD);
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    rdbPredicates.EqualTo(MEDIA_DATA_DB_IS_TRASH, "0");

    rdbPredicates.Limit(LcdLimit);
    rdbPredicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return false;
    }

    do {
        ThumbnailRdbData data;
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);

    resultSet.reset();
    return true;
}

bool ThumbnailUtils::QueryNoThumbnailInfos(ThumbRdbOpt &opts, vector<ThumbnailRdbData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_MODIFIED
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.IsNull(MEDIA_DATA_DB_THUMBNAIL);
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    rdbPredicates.EqualTo(MEDIA_DATA_DB_IS_TRASH, "0");

    rdbPredicates.Limit(THUMBNAIL_QUERY_MAX);
    rdbPredicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);

    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        if (err == E_EMPTY_VALUES_BUCKET) {
            return true;
        }
        return false;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return false;
    }

    do {
        ThumbnailRdbData data;
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);
    resultSet.reset();
    return true;
}

bool ThumbnailUtils::UpdateThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
    ValuesBucket values;
    int changedRows;
    if (data.thumbnailKey.empty() && data.lcdKey.empty()) {
        MEDIA_ERR_LOG("No key to update!");
        return false;
    }

    if (!data.thumbnailKey.empty()) {
        values.PutString(MEDIA_DATA_DB_THUMBNAIL, data.thumbnailKey);
    }

    if (!data.lcdKey.empty()) {
        values.PutString(MEDIA_DATA_DB_LCD, data.lcdKey);
        int64_t timeNow = UTCTimeSeconds();
        values.PutLong(MEDIA_DATA_DB_TIME_VISIT, timeNow);
    }

    MediaLibraryTracer tracer;
    tracer.Start("UpdateThumbnailInfo opts.store->Update");
    err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { opts.row });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return false;
    }
    std::vector<std::string> devices;
    opts.table = MEDIALIBRARY_TABLE;
    SyncPushTable(opts, devices);
    return true;
}

bool ThumbnailUtils::UpdateVisitTime(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
    if (!opts.networkId.empty()) {
        return DoUpdateRemoteThumbnail(opts, data, err);
    }

    ValuesBucket values;
    int changedRows;
    int64_t timeNow = UTCTimeSeconds();
    values.PutLong(MEDIA_DATA_DB_TIME_VISIT, timeNow);
    err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { opts.row });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return false;
    }
    return true;
}

bool ThumbnailUtils::QueryDeviceThumbnailRecords(ThumbRdbOpt &opts, std::vector<ThumbnailRdbData> &infos,
    int &err)
{
    vector<string> column = {
        REMOTE_THUMBNAIL_DB_FILE_ID,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD
    };
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, opts.udid);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    if (!CheckResultSetColumn(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetColumn failed %{public}d", err);
        return false;
    }

    ThumbnailRdbData data;
    do {
        ParseQueryResult(resultSet, data, err);
        infos.push_back(data);
    } while (resultSet->GoToNextRow() == E_OK);

    resultSet.reset();
    return true;
}

bool ThumbnailUtils::GetRemoteThumbnailInfo(ThumbRdbOpt &opts, const std::string &id,
    const std::string &udid, int &err)
{
    vector<string> column = {
        REMOTE_THUMBNAIL_DB_ID
    };
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_FILE_ID, id);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, udid);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }
    resultSet.reset();
    return true;
}

bool ThumbnailUtils::GetUdidByNetworkId(ThumbRdbOpt &opts, const std::string &networkId,
    std::string &outUdid, int &err)
{
    vector<string> column = {
        DEVICE_DB_ID,
        DEVICE_DB_UDID
    };
    RdbPredicates rdbPredicates(DEVICE_TABLE);
    rdbPredicates.EqualTo(DEVICE_DB_NETWORK_ID, networkId);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        return false;
    }
    int index;
    err = resultSet->GetColumnIndex(DEVICE_DB_UDID, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, outUdid, err);
    } else {
        MEDIA_ERR_LOG("Get column %{public}s index error %{public}d", DEVICE_DB_UDID.c_str(), err);
    }
    return true;
}

bool ThumbnailUtils::QueryRemoteThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
    if (data.udid.empty() && !GetUdidByNetworkId(opts, opts.networkId, data.udid, err)) {
        MEDIA_ERR_LOG("GetUdidByNetworkId failed! %{public}d", err);
        return false;
    }

    vector<string> column = {
        REMOTE_THUMBNAIL_DB_ID,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD
    };
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_FILE_ID, data.id);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, data.udid);
    shared_ptr<ResultSet> resultSet = opts.store->Query(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        return false;
    }

    int index;
    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_LCD, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.lcdKey, err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_THUMBNAIL, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.thumbnailKey, err);
    }
    return true;
}

static inline bool IsKeyNotSame(const string &newKey, const string &oldKey)
{
    if (!newKey.empty() && !oldKey.empty() && (newKey != oldKey)) {
        return true;
    }
    return false;
}

bool ThumbnailUtils::DoUpdateRemoteThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
    if (opts.networkId.empty()) {
        return false;
    }
    if (data.thumbnailKey.empty() && data.lcdKey.empty()) {
        return false;
    }
    ThumbnailData tmpData = data;
    auto isGot = ThumbnailUtils::QueryRemoteThumbnail(opts, tmpData, err);
    if (isGot) {
        if (IsKeyNotSame(data.thumbnailKey, tmpData.thumbnailKey)) {
            if (!RemoveDataFromKv(opts.kvStore, tmpData.thumbnailKey)) {
                return false;
            }
        }
        if (IsKeyNotSame(data.lcdKey, tmpData.lcdKey)) {
            if (!RemoveDataFromKv(opts.kvStore, tmpData.lcdKey)) {
                return false;
            }
        }
    }

    data.udid = tmpData.udid;
    if (isGot) {
        return UpdateRemoteThumbnailInfo(opts, data, err);
    } else {
        return InsertRemoteThumbnailInfo(opts, data, err);
    }
}

bool ThumbnailUtils::UpdateRemoteThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_FILE_ID, data.id);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, data.udid);

    ValuesBucket values;
    if (!data.thumbnailKey.empty()) {
        values.PutString(MEDIA_DATA_DB_THUMBNAIL, data.thumbnailKey);
    }

    if (!data.lcdKey.empty()) {
        values.PutString(MEDIA_DATA_DB_LCD, data.lcdKey);
        int64_t timeNow = UTCTimeSeconds();
        values.PutLong(MEDIA_DATA_DB_TIME_VISIT, timeNow);
    }

    int changedRows;
    err = opts.store->Update(changedRows, values, rdbPredicates);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return false;
    }

    return true;
}

bool ThumbnailUtils::InsertRemoteThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
    ValuesBucket values;
    values.PutInt(REMOTE_THUMBNAIL_DB_FILE_ID, std::stoi(data.id));
    values.PutString(REMOTE_THUMBNAIL_DB_UDID, data.udid);
    if (!data.thumbnailKey.empty()) {
        values.PutString(MEDIA_DATA_DB_THUMBNAIL, data.thumbnailKey);
    }

    if (!data.lcdKey.empty()) {
        values.PutString(MEDIA_DATA_DB_LCD, data.lcdKey);
        int64_t timeNow = UTCTimeSeconds();
        values.PutLong(MEDIA_DATA_DB_TIME_VISIT, timeNow);
    }

    int64_t outRowId = -1;
    err = opts.store->Insert(outRowId, REMOTE_THUMBNAIL_TABLE, values);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return false;
    }
    return true;
}

bool ThumbnailUtils::CleanThumbnailInfo(ThumbRdbOpt &opts, bool withThumb, bool withLcd)
{
    ValuesBucket values;
    if (withThumb) {
        values.PutNull(MEDIA_DATA_DB_THUMBNAIL);
    }
    if (withLcd) {
        values.PutNull(MEDIA_DATA_DB_LCD);
        values.PutLong(MEDIA_DATA_DB_TIME_VISIT, 0);
    }
    int changedRows;
    auto err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { opts.row });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return false;
    }
    return true;
}

bool ThumbnailUtils::CleanDistributeLcdInfo(ThumbRdbOpt &opts)
{
    string udid;
    int err;
    if (!GetUdidByNetworkId(opts, opts.networkId, udid, err)) {
        MEDIA_ERR_LOG("GetUdidByNetworkId failed! %{public}d", err);
        return false;
    }

    ValuesBucket values;
    values.PutNull(MEDIA_DATA_DB_LCD);
    values.PutLong(MEDIA_DATA_DB_TIME_VISIT, 0);
    int changedRows;
    vector<string> whereArgs = { udid, opts.row };
    string deleteCondition = REMOTE_THUMBNAIL_DB_UDID + " = ? AND " +
        REMOTE_THUMBNAIL_DB_FILE_ID + " = ?";
    auto ret = opts.store->Update(changedRows, REMOTE_THUMBNAIL_TABLE, values, deleteCondition, whereArgs);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Delete failed! %{public}d", ret);
        return false;
    }
    return true;
}

bool ThumbnailUtils::DeleteDistributeThumbnailInfo(ThumbRdbOpt &opts)
{
    int changedRows;
    vector<string> whereArgs = { opts.udid, opts.row };
    string deleteCondition = REMOTE_THUMBNAIL_DB_UDID + " = ? AND " +
        REMOTE_THUMBNAIL_DB_FILE_ID + " = ?";
    auto err = opts.store->Delete(changedRows, REMOTE_THUMBNAIL_TABLE, deleteCondition, whereArgs);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Delete failed! %{public}d", err);
        return false;
    }
    return true;
}

bool ThumbnailUtils::LoadSourceImage(ThumbnailData &data)
{
    if (data.source != nullptr) {
        return true;
    }
    MediaLibraryTracer tracer;
    tracer.Start("LoadSourceImage");

    bool ret = false;
    if (data.mediaType == MEDIA_TYPE_VIDEO) {
        ret = LoadVideoFile(data.path, data.source, data.degrees);
    } else if (data.mediaType == MEDIA_TYPE_AUDIO) {
        ret = LoadAudioFile(data.path, data.source, data.degrees);
    } else {
        ret = LoadImageFile(data.path, data.source, data.degrees);
    }

    return ret;
}

bool ThumbnailUtils::CreateThumbnailData(ThumbnailData &data)
{
    Size size = { DEFAULT_THUMBNAIL_SIZE, DEFAULT_THUMBNAIL_SIZE };
    MediaLibraryTracer tracer;
    tracer.Start("CompressImage");
    bool ret = CompressImage(data.source, size, data.thumbnail, data.degrees);
    return ret;
}

bool ThumbnailUtils::CreateLcdData(ThumbnailData &data, int32_t lcdSize)
{
    lcdSize = (lcdSize == 0) ? DEFAULT_LCD_SIZE : lcdSize;
    auto width = data.source->GetWidth();
    auto height = data.source->GetHeight();
    int32_t maxSize = 1;
    maxSize = max(maxSize, max(width, height));
    double scale = 1.0f;
    if (lcdSize < maxSize) {
        scale = (float) lcdSize / maxSize;
    }
    Size size = {
        static_cast<int32_t> (scale * width),
        static_cast<int32_t> (scale * height),
    };

    MediaLibraryTracer tracer;
    tracer.Start("CompressImage");
    bool ret = CompressImage(data.source, size, data.lcd, data.degrees);
    return ret;
}

Status ThumbnailUtils::SaveThumbnailData(ThumbnailData &data, const std::string &networkId,
    const shared_ptr<SingleKvStore> &kvStore)
{
    Status status = SaveImage(kvStore, data.thumbnailKey, data.thumbnail);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("SaveImage failed! status %{public}d", status);
        return status;
    }
    if (!networkId.empty()) {
        MediaLibraryTracer tracer;
        tracer.Start("SaveThumbnailData::SyncPushKvstore");
        auto syncStatus = SyncPushKvstore(kvStore, data.thumbnailKey, networkId);
        if (syncStatus != DistributedKv::Status::SUCCESS) {
            MEDIA_ERR_LOG("SyncPushKvstore failed! ret %{public}d", syncStatus);
            return syncStatus;
        }
    }

    return status;
}

Status ThumbnailUtils::SaveLcdData(ThumbnailData &data, const std::string &networkId,
    const shared_ptr<SingleKvStore> &kvStore)
{
    Status status = SaveImage(kvStore, data.lcdKey, data.lcd);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("SaveLcdData SaveImage failed! status %{public}d", status);
        return status;
    }
    if (!networkId.empty()) {
        MediaLibraryTracer tracer;
        tracer.Start("SaveLcdData::SyncPushKvstore");
        auto syncStatus = SyncPushKvstore(kvStore, data.lcdKey, networkId);
        if (syncStatus != DistributedKv::Status::SUCCESS) {
            MEDIA_ERR_LOG("SaveLcdData SyncPushKvstore failed! ret %{public}d", syncStatus);
            return syncStatus;
        }
    }
    return status;
}

int32_t ThumbnailUtils::SetSource(std::shared_ptr<AVMetadataHelper> avMetadataHelper, const std::string &path)
{
    if (avMetadataHelper == nullptr) {
        MEDIA_ERR_LOG("avMetadataHelper == nullptr");
        return E_ERR;
    }
    MEDIA_DEBUG_LOG("path = %{private}s", path.c_str());
    UriHelper uriHelper(path);
    if ((uriHelper.UriType() != UriHelper::URI_TYPE_FILE) && !uriHelper.AccessCheck(UriHelper::URI_READ)) {
        MEDIA_ERR_LOG("Invalid file Path %{private}s", path.c_str());
        return E_ERR;
    }
    std::string rawFile = uriHelper.FormattedUri();
    rawFile = rawFile.substr(strlen("file://"));
    int32_t fd = open(rawFile.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("Open file failed, err %{public}d", errno);
        return E_ERR;
    }

    struct stat64 st;
    if (fstat64(fd, &st) != 0) {
        MEDIA_ERR_LOG("Get file state failed, err %{public}d", errno);
        (void)close(fd);
        return E_ERR;
    }
    int64_t length = static_cast<int64_t>(st.st_size);
    int32_t ret = avMetadataHelper->SetSource(fd, 0, length, 1);
    if (ret != 0) {
        MEDIA_ERR_LOG("SetSource fail");
        (void)close(fd);
        return E_ERR;
    }
    (void)close(fd);
    return SUCCESS;
}

bool ThumbnailUtils::SyncPushTable(ThumbRdbOpt &opts, std::vector<std::string> &devices, bool isBlock)
{
    MEDIA_DEBUG_LOG("SyncPushTable table = %{public}s", opts.table.c_str());
    // start sync
    DistributedRdb::SyncOption option;
    option.mode = DistributedRdb::SyncMode::PUSH;
    option.isBlock = isBlock;

    NativeRdb::AbsRdbPredicates predicate(opts.table);
    (devices.size() > 0) ? predicate.InDevices(devices) : predicate.InAllDevices();

    DistributedRdb::SyncCallback callback = [](const DistributedRdb::SyncResult& syncResult) {
        // update device db
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (iter->first.empty()) {
                MEDIA_ERR_LOG("SyncPushTable deviceId is empty");
                continue;
            }
            if (iter->second != 0) {
                MEDIA_ERR_LOG("SyncPushTable device = %{private}s syncResult = %{private}d",
                    iter->first.c_str(), iter->second);
                continue;
            }
            MEDIA_ERR_LOG("SyncPushTable device = %{private}s success", iter->first.c_str());
        }
    };

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "SyncPushTable rdbStore->Sync");
    int ret = opts.store->Sync(option, predicate, callback);
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);

    return ret == E_OK;
}

bool ThumbnailUtils::SyncPullTable(ThumbRdbOpt &opts, std::vector<std::string> &devices, bool isBlock)
{
    MEDIA_DEBUG_LOG("SyncPullTable table = %{public}s", opts.table.c_str());
    DistributedRdb::SyncOption option;
    option.mode = DistributedRdb::SyncMode::PULL;
    option.isBlock = isBlock;

    NativeRdb::AbsRdbPredicates predicate(opts.table);
    (devices.size() > 0) ? predicate.InDevices(devices) : predicate.InAllDevices();
    if (!opts.row.empty()) {
        predicate.EqualTo(MEDIA_DATA_DB_ID, opts.row);
    }

    shared_ptr<SyncStatus> status = make_shared<SyncStatus>();
    DistributedRdb::SyncCallback callback = [status](const DistributedRdb::SyncResult& syncResult) {
        for (auto iter = syncResult.begin(); iter != syncResult.end(); iter++) {
            if (iter->second != 0) {
                MEDIA_ERR_LOG("SyncPullTable device = %{private}s syncResult = %{private}d",
                    iter->first.c_str(), iter->second);
                continue;
            }
            std::unique_lock<std::mutex> lock(status->mtx_);
            status->isSyncComplete_ = true;
        }
        status->cond_.notify_one();
    };

    MediaLibraryTracer tracer;
    tracer.Start("SyncPullTable rdbStore->Sync");
    int ret = opts.store->Sync(option, predicate, callback);
    if (ret != E_OK || !isBlock) {
        return ret == E_OK;
    }

    std::unique_lock<std::mutex> lock(status->mtx_);
    bool success = status->cond_.wait_for(lock, std::chrono::milliseconds(WAIT_FOR_MS),
        [status] { return status->isSyncComplete_; });
    if (success) {
        MEDIA_DEBUG_LOG("wait_for SyncCompleted");
    } else {
        MEDIA_INFO_LOG("wait_for timeout");
    }

    return true;
}

Status ThumbnailUtils::SyncPullKvstore(const shared_ptr<SingleKvStore> &kvStore, const string key,
    const string &networkId)
{
    MEDIA_DEBUG_LOG("networkId is %{private}s key is %{private}s",
        networkId.c_str(), key.c_str());
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("kvStore is null");
        return DistributedKv::Status::ERROR;
    }
    if (networkId.empty()) {
        MEDIA_ERR_LOG("networkId empty error");
        return DistributedKv::Status::ERROR;
    }

    DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    dataQuery.Limit(1, 0); // for force to sync single key
    std::vector<std::string> deviceIds = { networkId };
    MediaLibraryTracer tracer;
    tracer.Start("SyncPullKvstore kvStore->SyncPull");
    auto callback = std::make_shared<MediaLibrarySyncCallback>();
    Status status = kvStore->Sync(deviceIds, OHOS::DistributedKv::SyncMode::PULL, dataQuery, callback);
    if (!callback->WaitFor()) {
        MEDIA_DEBUG_LOG("wait_for timeout");
        status = Status::ERROR;
    }
    return status;
}

Status ThumbnailUtils::SyncPushKvstore(const shared_ptr<SingleKvStore> &kvStore, string key, const string &networkId)
{
    MEDIA_DEBUG_LOG("networkId is %{private}s", networkId.c_str());
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("kvStore is null");
        return Status::ERROR;
    }
    if (networkId.empty()) {
        MEDIA_ERR_LOG("networkId empty error");
        return Status::ERROR;
    }
    DistributedKv::DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    vector<string> deviceIds = { networkId };
    MediaLibraryTracer tracer;
    tracer.Start("SyncPushKvstore kvStore->SyncPush");
    return kvStore->Sync(deviceIds, OHOS::DistributedKv::SyncMode::PUSH, dataQuery);
}

bool ThumbnailUtils::ResizeImage(const vector<uint8_t> &data, const Size &size, unique_ptr<PixelMap> &pixelMap)
{
    MediaLibraryTracer tracer;
    tracer.Start("ResizeImage");
    if (data.size() == 0) {
        MEDIA_ERR_LOG("Data is empty");
        return false;
    }

    tracer.Start("ImageSource::CreateImageSource");
    uint32_t err = E_OK;
    SourceOptions opts;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data.data(),
        data.size(), opts, err);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to create image source %{public}d", err);
        return false;
    }
    tracer.Finish();

    tracer.Start("imageSource->CreatePixelMap");
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = size.width;
    decodeOpts.desiredSize.height = size.height;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    if (err != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create pixelmap %{public}d", err);
        return false;
    }

    return true;
}

bool ThumbnailUtils::GetKvResultSet(const shared_ptr<SingleKvStore> &kvStore, const string &key,
    const std::string &networkId, shared_ptr<DataShare::ResultSetBridge> &outResultSet)
{
    if (key.empty()) {
        MEDIA_ERR_LOG("key empty");
        return false;
    }

    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("KvStore is not init");
        return false;
    }

    MediaLibraryTracer tracer;
    tracer.Start("GetKey kvStore->Get");
    shared_ptr<SingleKvStore> singleKv = kvStore;
    outResultSet = shared_ptr<DataShare::ResultSetBridge>(ThumbnailDataShareBridge::Create(singleKv, key));
    return true;
}

bool ThumbnailUtils::RemoveDataFromKv(const shared_ptr<SingleKvStore> &kvStore, const string &key)
{
    if (key.empty()) {
        MEDIA_ERR_LOG("RemoveLcdFromKv key empty");
        return false;
    }

    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("KvStore is not init");
        return false;
    }

    MediaLibraryTracer tracer;
    tracer.Start("RemoveLcdFromKv kvStore->Get");
    auto status = kvStore->Delete(key);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("Failed to get key [%{public}s] ret [%{public}d]", key.c_str(), status);
        return false;
    }
    return true;
}

bool ThumbnailUtils::DeleteOriginImage(ThumbRdbOpt &opts, ThumbnailData &thumbnailData)
{
    ThumbnailData tmpData;
    int err = 0;
    auto rdbSet = QueryThumbnailInfo(opts, tmpData, err);
    if (rdbSet == nullptr) {
        MEDIA_ERR_LOG("QueryThumbnailInfo Faild [ %{public}d ]", err);
        return false;
    }

    if (IsKeyNotSame(tmpData.thumbnailKey, thumbnailData.thumbnailKey)) {
        if (!ThumbnailUtils::RemoveDataFromKv(opts.kvStore, tmpData.thumbnailKey)) {
            MEDIA_ERR_LOG("DeleteThumbnailData Faild");
            return false;
        }
    }
    if (IsKeyNotSame(tmpData.lcdKey, thumbnailData.lcdKey)) {
        if (!ThumbnailUtils::RemoveDataFromKv(opts.kvStore, tmpData.lcdKey)) {
            MEDIA_ERR_LOG("DeleteLCDlData Faild");
            return false;
        }
    }
    return true;
}

bool ThumbnailUtils::IsImageExist(const string &key, const string &networkId, const shared_ptr<SingleKvStore> &kvStore)
{
    if (key.empty()) {
        return false;
    }

    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("KvStore is not init");
        return false;
    }

    bool ret = false;
    DataQuery query;
    query.InKeys({key});
    int count = 0;
    auto status = kvStore->GetCount(query, count);
    if (status == Status::SUCCESS && count > 0) {
        MEDIA_DEBUG_LOG("kvStore_->GetCount key [%{public}s] status %{public}d", key.c_str(), status);
        ret = true;
    }

    if (!ret) {
        MEDIA_DEBUG_LOG("IsImageExist failed!, key [%{public}s]", key.c_str());
        if (!networkId.empty()) {
            MediaLibraryTracer tracer;
            tracer.Start("SyncPullKvstore");
            auto syncStatus = SyncPullKvstore(kvStore, key, networkId);
            if (syncStatus == DistributedKv::Status::SUCCESS) {
                MEDIA_DEBUG_LOG("SyncPullKvstore SUCCESS");
                return true;
            } else {
                MEDIA_ERR_LOG("SyncPullKvstore failed! ret %{public}d", syncStatus);
                return false;
            }
        }
    }
    return ret;
}

void ThumbnailUtils::ThumbnailDataCopy(ThumbnailData &data, ThumbnailRdbData &rdbData)
{
    data.id = rdbData.id;
    data.path = rdbData.path;
    data.thumbnailKey = rdbData.thumbnailKey;
    data.lcdKey = rdbData.lcdKey;
    data.mediaType = rdbData.mediaType;
    data.dateModified = rdbData.dateModified;
}

int64_t ThumbnailUtils::UTCTimeSeconds()
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)(t.tv_sec);
}

bool ThumbnailUtils::CheckResultSetCount(const shared_ptr<ResultSet> &resultSet, int &err)
{
    if (resultSet == nullptr) {
        return false;
    }
    int rowCount = 0;
    err = resultSet->GetRowCount(rowCount);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{public}d", err);
        return false;
    }

    if (rowCount <= 0) {
        MEDIA_ERR_LOG("CheckCount No match!");
        err = E_EMPTY_VALUES_BUCKET;
        return false;
    }

    return true;
}

bool ThumbnailUtils::CheckResultSetColumn(const shared_ptr<ResultSet> &resultSet, int &err)
{
    if (resultSet == nullptr) {
        return false;
    }
    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        return false;
    }

    int columnCount = 0;
    err = resultSet->GetColumnCount(columnCount);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get column count %{public}d", err);
        return false;
    }

    if (columnCount <= 0) {
        MEDIA_ERR_LOG("No column!");
        err = E_EMPTY_VALUES_BUCKET;
        return false;
    }

    return true;
}

void ThumbnailUtils::ParseStringResult(const shared_ptr<ResultSet> &resultSet, int index, string &data, int &err)
{
    bool isNull = true;
    err = resultSet->IsColumnNull(index, isNull);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to check column %{public}d null %{public}d", index, err);
    }

    if (!isNull) {
        err = resultSet->GetString(index, data);
        if (err != E_OK) {
            MEDIA_ERR_LOG("Failed to get column %{public}d string %{public}d", index, err);
        }
    }
}

void ThumbnailUtils::ParseQueryResult(const shared_ptr<ResultSet> &resultSet, ThumbnailRdbData &data, int &err)
{
    int index;
    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.id, err);
    } else {
        MEDIA_ERR_LOG("Get column %{public}s index error %{public}d", MEDIA_DATA_DB_ID.c_str(), err);
    }

    err = resultSet->GetColumnIndex(REMOTE_THUMBNAIL_DB_FILE_ID, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.id, err);
    } else {
        MEDIA_ERR_LOG("Get column %{public}s index error %{public}d", MEDIA_DATA_DB_ID.c_str(), err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.path, err);
    } else {
        MEDIA_ERR_LOG("Get column %{private}s index error %{private}d", MEDIA_DATA_DB_FILE_PATH.c_str(), err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_THUMBNAIL, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.thumbnailKey, err);
    } else {
        MEDIA_ERR_LOG("Get column %{public}s index error %{public}d", MEDIA_DATA_DB_THUMBNAIL.c_str(), err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_LCD, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.lcdKey, err);
    } else {
        MEDIA_ERR_LOG("Get column %{public}s index error %{public}d", MEDIA_DATA_DB_LCD.c_str(), err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, index);
    if (err == NativeRdb::E_OK) {
        data.mediaType = MediaType::MEDIA_TYPE_ALL;
        err = resultSet->GetInt(index, data.mediaType);
    } else {
        MEDIA_ERR_LOG("Get column %{public}s index error %{public}d", MEDIA_DATA_DB_MEDIA_TYPE.c_str(), err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_DATE_MODIFIED, index);
    if (err == NativeRdb::E_OK) {
        err = resultSet->GetLong(index, data.dateModified);
    } else {
        MEDIA_ERR_LOG("Get column %{public}s index error %{public}d", MEDIA_DATA_DB_DATE_MODIFIED.c_str(), err);
    }
}

void MediaLibrarySyncCallback::SyncCompleted(const map<std::string, DistributedKv::Status> &results)
{
    for (auto &item : results) {
        if (item.second == Status::SUCCESS) {
            MEDIA_DEBUG_LOG("ThumbnailUtils::SyncCompleted OK");
            std::unique_lock<std::mutex> lock(status_.mtx_);
            status_.isSyncComplete_ = true;
            break;
        }
    }
    status_.cond_.notify_one();
}

bool MediaLibrarySyncCallback::WaitFor()
{
    std::unique_lock<std::mutex> lock(status_.mtx_);
    bool ret = status_.cond_.wait_for(lock, std::chrono::milliseconds(WAIT_FOR_MS),
        [this]() { return status_.isSyncComplete_; });
    if (!ret) {
        MEDIA_INFO_LOG("ThumbnailUtils::SyncPullKvstore wait_for timeout");
    } else {
        MEDIA_DEBUG_LOG("ThumbnailUtils::SyncPullKvstore wait_for SyncCompleted");
    }
    return ret;
}
} // namespace Media
} // namespace OHOS
