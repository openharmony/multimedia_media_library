/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include <malloc.h>
#include <sys/stat.h>

#include "cloud_sync_helper.h"
#include "datashare_abs_result_set.h"
#ifdef DISTRIBUTED
#include "device_manager.h"
#endif
#include "dfx_utils.h"
#include "distributed_kv_data_manager.h"
#include "hitrace_meter.h"
#include "image_packer.h"
#include "ipc_skeleton.h"
#include "media_column.h"
#ifdef DISTRIBUTED
#include "media_device_column.h"
#endif
#include "media_exif.h"
#include "media_remote_thumbnail_column.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_sync_operation.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "mimetype_utils.h"
#include "parameter.h"
#include "post_proc.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "thumbnail_const.h"
#include "thumbnail_source_loading.h"
#include "unique_fd.h"
#include "post_event_utils.h"
#include "dfx_manager.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

#ifdef DISTRIBUTED
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
#endif

static string GetThumbnailSuffix(ThumbnailType type)
{
    string suffix;
    switch (type) {
        case ThumbnailType::THUMB:
            suffix = THUMBNAIL_THUMB_SUFFIX;
            break;
        case ThumbnailType::THUMB_ASTC:
            suffix = THUMBNAIL_THUMBASTC_SUFFIX;
            break;
        case ThumbnailType::LCD:
            suffix = THUMBNAIL_LCD_SUFFIX;
            break;
        default:
            return "";
    }
    return suffix;
}

bool ThumbnailUtils::DeleteThumbFile(ThumbnailData &data, ThumbnailType type)
{
    string fileName = GetThumbnailPath(data.path, GetThumbnailSuffix(type));
    if (!MediaFileUtils::DeleteFile(fileName)) {
        MEDIA_ERR_LOG("delete file faild %{public}d", errno);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, -errno},
            {KEY_OPT_FILE, fileName}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    return true;
}

bool ThumbnailUtils::LoadAudioFileInfo(shared_ptr<AVMetadataHelper> avMetadataHelper, ThumbnailData &data,
    Size &desiredSize, uint32_t &errCode)
{
    auto audioPicMemory = avMetadataHelper->FetchArtPicture();
    if (audioPicMemory == nullptr) {
        MEDIA_ERR_LOG("FetchArtPicture failed!");
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
            {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    SourceOptions opts;
    unique_ptr<ImageSource> audioImageSource = ImageSource::CreateImageSource(audioPicMemory->GetBase(),
        audioPicMemory->GetSize(), opts, errCode);
    if (audioImageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to create image source! path %{private}s errCode %{public}d", data.path.c_str(), errCode);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, static_cast<int32_t>(errCode)}, {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    ImageInfo imageInfo;
    errCode = audioImageSource->GetImageInfo(0, imageInfo);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to get image info, path: %{private}s err: %{public}d", data.path.c_str(), errCode);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, static_cast<int32_t>(errCode)}, {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    data.stats.sourceWidth = imageInfo.size.width;
    data.stats.sourceHeight = imageInfo.size.height;

    DecodeOptions decOpts;
    decOpts.desiredSize = ConvertDecodeSize(data, imageInfo.size, desiredSize);
    decOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    data.source = audioImageSource->CreatePixelMap(decOpts, errCode);
    if ((errCode != E_OK) || (data.source == nullptr)) {
        MEDIA_ERR_LOG("Av meta data helper fetch frame at time failed");
        if (errCode != E_OK) {
            VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
                {KEY_ERR_CODE, static_cast<int32_t>(errCode)}, {KEY_OPT_FILE, data.path},
                {KEY_OPT_TYPE, OptType::THUMB}};
            PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        }
        return false;
    }
    return true;
}

bool ThumbnailUtils::LoadAudioFile(ThumbnailData &data, Size &desiredSize)
{
    shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    string path = data.path;
    int32_t err = SetSource(avMetadataHelper, path);
    if (err != E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);

        MEDIA_ERR_LOG("Av meta data helper set source failed %{public}d", err);
        return false;
    }
    uint32_t errCode = 0;
    if (!LoadAudioFileInfo(avMetadataHelper, data, desiredSize, errCode)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, static_cast<int32_t>(errCode)}, {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    return true;
}

bool ThumbnailUtils::LoadVideoFile(ThumbnailData &data, Size &desiredSize)
{
    shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    string path = data.path;
    int32_t err = SetSource(avMetadataHelper, path);
    if (err != 0) {
        return false;
    }
    PixelMapParams param;
    param.colorFormat = PixelFormat::RGBA_8888;
    data.source = avMetadataHelper->FetchFrameAtTime(AV_FRAME_TIME, AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC,
        param);
    if (data.source == nullptr) {
        DfxManager::GetInstance()->HandleThumbnailError(path, DfxType::AV_FETCH_FRAME, err);
        return false;
    }
    int width = data.source->GetWidth();
    int height = data.source->GetHeight();
    ConvertDecodeSize(data, {width, height}, desiredSize);
    if ((desiredSize.width != data.source->GetWidth() || desiredSize.height != data.source->GetHeight())) {
        param.dstWidth = desiredSize.width;
        param.dstHeight = desiredSize.height;
        data.source = avMetadataHelper->FetchFrameAtTime(AV_FRAME_TIME, AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC,
            param);
        if (data.source == nullptr) {
            DfxManager::GetInstance()->HandleThumbnailError(path, DfxType::AV_FETCH_FRAME, err);
            return false;
        }
    }
    data.stats.sourceWidth = data.source->GetWidth();
    data.stats.sourceHeight = data.source->GetHeight();
    DfxManager::GetInstance()->HandleHighMemoryThumbnail(path, MEDIA_TYPE_VIDEO, desiredSize.width, desiredSize.height);
    return true;
}

// gen pixelmap from data.souce, should ensure source is not null
bool ThumbnailUtils::GenTargetPixelmap(ThumbnailData &data, const Size &desiredSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("GenTargetPixelmap");
    if (data.source == nullptr) {
        return false;
    }

    if (!ScaleFastThumb(data, desiredSize)) {
        return false;
    }

    float widthScale = (1.0f * desiredSize.width) / data.source->GetWidth();
    float heightScale = (1.0f * desiredSize.height) / data.source->GetHeight();
    data.source->scale(widthScale, heightScale);
    return true;
}

bool ThumbnailUtils::ScaleTargetPixelMap(ThumbnailData &data, const Size &targetSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::ScaleTargetPixelMap");

    PostProc postProc;
    if (!postProc.ScalePixelMapEx(targetSize, *data.source, Media::AntiAliasingOption::HIGH)) {
        MEDIA_ERR_LOG("thumbnail scale failed [%{private}s]", data.id.c_str());
        return false;
    }
    return true;
}

bool ThumbnailUtils::LoadImageFile(ThumbnailData &data, Size &desiredSize)
{
    mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_DISABLE);
    mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);

    SourceLoader sourceLoader(desiredSize, data);
    return sourceLoader.RunLoading();
}

bool ThumbnailUtils::CompressImage(shared_ptr<PixelMap> &pixelMap, vector<uint8_t> &data, bool isHigh,
    shared_ptr<string> pathPtr, bool isAstc)
{
    string path;
    if (pathPtr != nullptr) {
        path = *pathPtr;
    }
    PackOption option = {
        .format = isAstc ? THUMBASTC_FORMAT : THUMBNAIL_FORMAT,
        .quality = isAstc ? ASTC_LOW_QUALITY : (isHigh ? THUMBNAIL_HIGH : THUMBNAIL_MID),
        .numberHint = NUMBER_HINT_1
    };
    data.resize(max(pixelMap->GetByteCount(), MIN_COMPRESS_BUF_SIZE));

    MediaLibraryTracer tracer;
    tracer.Start("imagePacker.StartPacking");
    ImagePacker imagePacker;
    uint32_t err = imagePacker.StartPacking(data.data(), data.size(), option);
    tracer.Finish();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to StartPacking %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, static_cast<int32_t>(err)},
            {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    tracer.Start("imagePacker.AddImage");
    err = imagePacker.AddImage(*pixelMap);
    tracer.Finish();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to StartPacking %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, static_cast<int32_t>(err)},
            {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    tracer.Start("imagePacker.FinalizePacking");
    int64_t packedSize = 0;
    err = imagePacker.FinalizePacking(packedSize);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to StartPacking %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, static_cast<int32_t>(err)},
            {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    data.resize(packedSize);
    return true;
}

shared_ptr<ResultSet> ThumbnailUtils::QueryThumbnailSet(ThumbRdbOpt &opts)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_MEDIA_TYPE,
    };

    vector<string> selectionArgs;
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + opts.row;

    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.SetWhereClause(strQueryCondition);
    rdbPredicates.SetWhereArgs(selectionArgs);
    return opts.store->QueryByStep(rdbPredicates, column);
}

shared_ptr<ResultSet> ThumbnailUtils::QueryThumbnailInfo(ThumbRdbOpt &opts,
    ThumbnailData &data, int &err)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnailInfo");
    auto resultSet = QueryThumbnailSet(opts);
    if (!CheckResultSetCount(resultSet, err)) {
        return nullptr;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    ParseQueryResult(resultSet, data, err);
    return resultSet;
}

bool ThumbnailUtils::QueryLcdCount(ThumbRdbOpt &opts, int &outLcdCount, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
    };
    RdbPredicates rdbPredicates(opts.table);
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        rdbPredicates.EqualTo(PhotoColumn::PHOTO_LAST_VISIT_TIME, "0");
    }
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    auto resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    int rowCount = 0;
    err = resultSet->GetRowCount(rowCount);
    resultSet.reset();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    MEDIA_DEBUG_LOG("rowCount is %{public}d", rowCount);
    if (rowCount <= 0) {
        MEDIA_INFO_LOG("No match! %{private}s", rdbPredicates.ToString().c_str());
        rowCount = 0;
    }

    outLcdCount = rowCount;
    return true;
}

bool ThumbnailUtils::QueryLcdCountByTime(const int64_t &time, const bool &before, ThumbRdbOpt &opts, int &outLcdCount,
    int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
    };
    RdbPredicates rdbPredicates(opts.table);
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        if (before) {
            rdbPredicates.LessThanOrEqualTo(PhotoColumn::PHOTO_LAST_VISIT_TIME, to_string(time));
        } else {
            rdbPredicates.GreaterThan(PhotoColumn::PHOTO_LAST_VISIT_TIME, to_string(time));
        }
    }
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    auto resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    int rowCount = 0;
    err = resultSet->GetRowCount(rowCount);
    resultSet.reset();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    MEDIA_DEBUG_LOG("rowCount is %{public}d", rowCount);
    if (rowCount <= 0) {
        MEDIA_INFO_LOG("No match! %{private}s", rdbPredicates.ToString().c_str());
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
    auto resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (resultSet == nullptr) {
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
        MEDIA_INFO_LOG("No match! %{private}s", rdbPredicates.ToString().c_str());
        rowCount = 0;
    }
    outLcdCount = rowCount;
    return true;
}

#ifdef DISTRIBUTED
bool ThumbnailUtils::QueryAgingDistributeLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
    vector<ThumbnailData> &infos, int &err)
{
    vector<string> column = {
        REMOTE_THUMBNAIL_DB_FILE_ID,
        MEDIA_DATA_DB_LCD
    };
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.IsNotNull(MEDIA_DATA_DB_LCD);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, opts.udid);

    rdbPredicates.Limit(LcdLimit);
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        return false;
    }

    ThumbnailData data;
    do {
        ParseQueryResult(resultSet, data, err);
        if (!data.lcdKey.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);
    return true;
}
#endif

bool ThumbnailUtils::QueryAgingLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
    vector<ThumbnailData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_MEDIA_TYPE,
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));

    rdbPredicates.Limit(LcdLimit);
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        rdbPredicates.OrderByAsc(PhotoColumn::PHOTO_LAST_VISIT_TIME);
    }
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        return false;
    }

    ThumbnailData data;
    do {
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);
    return true;
}

bool ThumbnailUtils::QueryNoLcdInfos(ThumbRdbOpt &opts, int LcdLimit, vector<ThumbnailData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_MEDIA_TYPE,
    };
    RdbPredicates rdbPredicates(opts.table);
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        rdbPredicates.EqualTo(PhotoColumn::PHOTO_LAST_VISIT_TIME, "0");
    }
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    if ((opts.table == PhotoColumn::PHOTOS_TABLE) || (opts.table == AudioColumn::AUDIOS_TABLE)) {
        rdbPredicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, "0");
    } else {
        rdbPredicates.EqualTo(MEDIA_DATA_DB_IS_TRASH, "0");
    }
    rdbPredicates.EqualTo(MEDIA_DATA_DB_TIME_PENDING, "0");
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        // Filter data that Only exists in Cloud to avoid cosuming data of downloading the original image
        // meaning of Position: 1--only in local, 2--only in cloud, 3--both in local and cloud
        rdbPredicates.BeginWrap()->EqualTo(PhotoColumn::PHOTO_POSITION, "1")->Or()->
            EqualTo(PhotoColumn::PHOTO_POSITION, "3")->EndWrap();
    }

    rdbPredicates.Limit(LcdLimit);
    rdbPredicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }

    ThumbnailData data;
    do {
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);
    return true;
}

bool ThumbnailUtils::QueryNoThumbnailInfos(ThumbRdbOpt &opts, vector<ThumbnailData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_MEDIA_TYPE,
    };
    RdbPredicates rdbPredicates(opts.table);
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        rdbPredicates.EqualTo(PhotoColumn::PHOTO_LAST_VISIT_TIME, "0");
    }
    if ((opts.table == PhotoColumn::PHOTOS_TABLE) || (opts.table == AudioColumn::AUDIOS_TABLE)) {
        rdbPredicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, "0");
    } else {
        rdbPredicates.EqualTo(MEDIA_DATA_DB_IS_TRASH, "0");
    }
    rdbPredicates.EqualTo(MEDIA_DATA_DB_TIME_PENDING, "0");
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        // Filter data that Only exists in Cloud to avoid cosuming data of downloading the original image
        // meaning of Position: 1--only in local, 2--only in cloud, 3--both in local and cloud
        rdbPredicates.BeginWrap()->EqualTo(PhotoColumn::PHOTO_POSITION, "1")->Or()->
            EqualTo(PhotoColumn::PHOTO_POSITION, "3")->EndWrap();
    }

    rdbPredicates.Limit(THUMBNAIL_QUERY_MAX);
    rdbPredicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);

    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        if (err == E_EMPTY_VALUES_BUCKET) {
            return true;
        }
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }

    ThumbnailData data;
    do {
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);
    return true;
}

bool ThumbnailUtils::QueryNoAstcInfos(ThumbRdbOpt &opts, vector<ThumbnailData> &infos, int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_ADDED,
        MEDIA_DATA_DB_NAME,
    };
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.EqualTo(PhotoColumn::PHOTO_HAS_ASTC, "0");
    rdbPredicates.BeginWrap()->EqualTo(PhotoColumn::PHOTO_POSITION, "1")->Or()->
        EqualTo(PhotoColumn::PHOTO_POSITION, "3")->EndWrap();
    rdbPredicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        if (err == E_EMPTY_VALUES_BUCKET) {
            return true;
        }
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }

    ThumbnailData data;
    do {
        ParseQueryResult(resultSet, data, err);
        if (!data.path.empty()) {
            infos.push_back(data);
        }
    } while (resultSet->GoToNextRow() == E_OK);
    return true;
}

bool ThumbnailUtils::QueryNewThumbnailCount(ThumbRdbOpt &opts, const int64_t &time, int &count,
    int &err)
{
    vector<string> column = {
        MEDIA_DATA_DB_ID,
    };
    RdbPredicates rdbPredicates(opts.table);
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        rdbPredicates.GreaterThan(PhotoColumn::PHOTO_LAST_VISIT_TIME, to_string(time));
    }
    if (opts.table == MEDIALIBRARY_TABLE) {
        rdbPredicates.EqualTo(MEDIA_DATA_DB_IS_TRASH, "0");
    } else {
        rdbPredicates.EqualTo(MEDIA_DATA_DB_DATE_TRASHED, "0");
    }
    rdbPredicates.EqualTo(MEDIA_DATA_DB_TIME_PENDING, "0");
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM));
    rdbPredicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_FILE));

    rdbPredicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);

    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    int rowCount = 0;
    err = resultSet->GetRowCount(rowCount);
    resultSet.reset();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    MEDIA_DEBUG_LOG("rowCount is %{public}d", rowCount);
    if (rowCount <= 0) {
        MEDIA_INFO_LOG("No match! %{public}s", rdbPredicates.ToString().c_str());
        rowCount = 0;
    }

    count = rowCount;
    return true;
}

bool ThumbnailUtils::UpdateLcdInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
    ValuesBucket values;
    int changedRows;

    MediaLibraryTracer tracer;
    tracer.Start("UpdateLcdInfo opts.store->Update");
    int64_t timeNow = UTCTimeMilliSeconds();
    values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, timeNow);
    err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { opts.row });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    return true;
}

bool ThumbnailUtils::UpdateVisitTime(ThumbRdbOpt &opts, ThumbnailData &data, int &err)
{
#ifdef DISTRIBUTED
    if (!opts.networkId.empty()) {
        return DoUpdateRemoteThumbnail(opts, data, err);
    }
#endif

    ValuesBucket values;
    int changedRows;
    int64_t timeNow = UTCTimeMilliSeconds();
    values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, timeNow);
    err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { opts.row });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    return true;
}

#ifdef DISTRIBUTED
bool ThumbnailUtils::QueryDeviceThumbnailRecords(ThumbRdbOpt &opts, vector<ThumbnailData> &infos,
    int &err)
{
    vector<string> column = {
        REMOTE_THUMBNAIL_DB_FILE_ID,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD
    };
    RdbPredicates rdbPredicates(REMOTE_THUMBNAIL_TABLE);
    rdbPredicates.EqualTo(REMOTE_THUMBNAIL_DB_UDID, opts.udid);
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed %{public}d", err);
        return false;
    }

    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }

    ThumbnailData data;
    do {
        ParseQueryResult(resultSet, data, err);
        infos.push_back(data);
    } while (resultSet->GoToNextRow() == E_OK);
    return true;
}

bool ThumbnailUtils::GetUdidByNetworkId(ThumbRdbOpt &opts, const string &networkId,
    string &outUdid, int &err)
{
    vector<string> column = {
        DEVICE_DB_ID,
        DEVICE_DB_UDID
    };
    RdbPredicates rdbPredicates(DEVICE_TABLE);
    rdbPredicates.EqualTo(DEVICE_DB_NETWORK_ID, networkId);
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
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
        MEDIA_ERR_LOG("Get column index error %{public}d", err);
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
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);
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
    return !newKey.empty() && !oldKey.empty() && (newKey != oldKey);
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
    values.PutInt(REMOTE_THUMBNAIL_DB_FILE_ID, stoi(data.id));
    values.PutString(REMOTE_THUMBNAIL_DB_UDID, data.udid);
    if (!data.thumbnailKey.empty()) {
        values.PutString(MEDIA_DATA_DB_THUMBNAIL, data.thumbnailKey);
    }

    if (!data.lcdKey.empty()) {
        values.PutString(MEDIA_DATA_DB_LCD, data.lcdKey);
    }

    int64_t outRowId = -1;
    err = opts.store->Insert(outRowId, REMOTE_THUMBNAIL_TABLE, values);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return false;
    }
    return true;
}
#endif

bool ThumbnailUtils::CleanThumbnailInfo(ThumbRdbOpt &opts, bool withThumb, bool withLcd)
{
    ValuesBucket values;
    if (withThumb) {
        values.PutNull(MEDIA_DATA_DB_THUMBNAIL);
    }
    if (withLcd) {
        values.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
        if (opts.table == MEDIALIBRARY_TABLE) {
            values.PutNull(MEDIA_DATA_DB_LCD);
        }
        if (opts.table == PhotoColumn::PHOTOS_TABLE) {
            values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, 0);
        }
    }
    int changedRows;
    auto err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { opts.row });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    return true;
}

#ifdef DISTRIBUTED
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
#endif

bool ThumbnailUtils::LoadSourceImage(ThumbnailData &data)
{
    if (data.source != nullptr) {
        return true;
    }
    MediaLibraryTracer tracer;
    tracer.Start("LoadSourceImage");
    if (data.mediaType == -1) {
        auto extension = MediaFileUtils::GetExtensionFromPath(data.path);
        auto mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extension);
        data.mediaType = MimeTypeUtils::GetMediaTypeFromMimeType(mimeType);
    }

    bool ret = false;
    data.degrees = 0.0;
    Size desiredSize;
    if (data.mediaType == MEDIA_TYPE_VIDEO) {
        ret = LoadVideoFile(data, desiredSize);
    } else if (data.mediaType == MEDIA_TYPE_AUDIO) {
        ret = LoadAudioFile(data, desiredSize);
    } else {
        ret = LoadImageFile(data, desiredSize);
    }
    if (!ret || (data.source == nullptr)) {
        return false;
    }
    tracer.Finish();

    if (data.useThumbAsSource) {
        tracer.Start("CenterScale");
        PostProc postProc;
        if (!postProc.CenterScale(desiredSize, *data.source)) {
            MEDIA_ERR_LOG("thumbnail center crop failed [%{private}s]", data.id.c_str());
            return false;
        }
    }
    data.source->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    if (std::abs(data.degrees - FLOAT_ZERO) > EPSILON) {
        data.source->rotate(data.degrees);
    }
    if (static_cast<int>(data.degrees) % FLAT_ANGLE != 0) {
        std::swap(data.lcdDesiredSize.width, data.lcdDesiredSize.height);
        std::swap(data.thumbDesiredSize.width, data.thumbDesiredSize.height);
    }

    // PixelMap has been rotated, fix the exif orientation to zero degree.
    data.source->ModifyImageProperty(PHOTO_DATA_IMAGE_ORIENTATION, DEFAULT_EXIF_ORIENTATION);
    return true;
}

bool ThumbnailUtils::ScaleFastThumb(ThumbnailData &data, const Size &size)
{
    MediaLibraryTracer tracer;
    tracer.Start("ScaleFastThumb");

    PostProc postProc;
    if (!postProc.CenterScale(size, *data.source)) {
        MEDIA_ERR_LOG("thumbnail center crop failed [%{private}s]", data.id.c_str());
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
            {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    return true;
}

static string Desensitize(string &str)
{
    string result = str;
    auto index = result.find('/');
    if (index == string::npos) {
        return "*****";
    }
    
    result.replace(0, index, index, '*');
    return result;
}

static int SaveFile(const string &fileName, uint8_t *output, int writeSize)
{
    string tempFileName = fileName + ".tmp";
    const mode_t fileMode = 0664;
    mode_t mask = umask(0);
    UniqueFd fd(open(tempFileName.c_str(), O_WRONLY | O_CREAT | O_TRUNC, fileMode));
    umask(mask);
    if (fd.Get() < 0) {
        if (errno == EEXIST) {
            UniqueFd fd(open(tempFileName.c_str(), O_WRONLY | O_TRUNC, fileMode));
        }
        if (fd.Get() < 0) {
            MEDIA_ERR_LOG("save failed! status %{public}d, filePath: %{public}s exists: %{public}d, parent path "
                "exists: %{public}d", errno, Desensitize(tempFileName).c_str(), MediaFileUtils::IsFileExists(
                    tempFileName), MediaFileUtils::IsFileExists(MediaFileUtils::GetParentPath(tempFileName)));
            return -errno;
        }
    }
    int ret = write(fd.Get(), output, writeSize);
    if (ret < 0) {
        MEDIA_ERR_LOG("write failed errno %{public}d", errno);
        return -errno;
    }
    int32_t errCode = fsync(fd.Get());
    if (errCode < 0) {
        MEDIA_ERR_LOG("fsync failed errno %{public}d", errno);
        return -errno;
    }
    close(fd.Release());

    if (MediaFileUtils::IsFileExists(fileName)) {
        MEDIA_INFO_LOG("file: %{public}s exists and needs to be deleted", Desensitize(tempFileName).c_str());
        if (!MediaFileUtils::DeleteFile(fileName)) {
            MEDIA_ERR_LOG("delete file: %{public}s failed", Desensitize(tempFileName).c_str());
            return -errno;
        }
    }
    errCode = MediaFileUtils::ModifyAsset(tempFileName, fileName);
    if (errCode != E_OK) {
        int32_t lastErrno = errno;
        if (!MediaFileUtils::DeleteFile(tempFileName)) {
            MEDIA_WARN_LOG("Delete tmp thumb error: %{public}d, name: %{private}s", errno, tempFileName.c_str());
        }
        if (errCode == E_FILE_EXIST || (errCode == E_FILE_OPER_FAIL && lastErrno == EEXIST)) {
            return E_OK;
        }
        return errCode;
    }
    return ret;
}

int ThumbnailUtils::SaveFileCreateDir(const string &path, const string &suffix, string &fileName)
{
    fileName = GetThumbnailPath(path, suffix);
    string dir = MediaFileUtils::GetParentPath(fileName);
    if (!MediaFileUtils::CreateDirectory(dir)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, -errno},
            {KEY_OPT_FILE, dir}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return -errno;
    }
    return E_OK;
}

int ThumbnailUtils::ToSaveFile(ThumbnailData &data, const ThumbnailType &type, const string &fileName,
    uint8_t *output, const int &writeSize)
{
    int ret = SaveFile(fileName, output, writeSize);
    if (ret < 0) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, ret},
            {KEY_OPT_FILE, fileName}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return ret;
    } else if (ret != writeSize) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_NO_SPACE},
            {KEY_OPT_FILE, fileName}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return E_NO_SPACE;
    }
    return E_OK;
}

int ThumbnailUtils::TrySaveFile(ThumbnailData &data, ThumbnailType type)
{
    string suffix;
    uint8_t *output;
    uint32_t writeSize;
    switch (type) {
        case ThumbnailType::THUMB:
            suffix = THUMBNAIL_THUMB_SUFFIX;
            output = data.thumbnail.data();
            writeSize = data.thumbnail.size();
            break;
        case ThumbnailType::THUMB_ASTC:
            suffix = THUMBNAIL_THUMBASTC_SUFFIX;
            output = data.thumbAstc.data();
            writeSize = data.thumbAstc.size();
            break;
        case ThumbnailType::LCD:
            suffix = THUMBNAIL_LCD_SUFFIX;
            output = data.lcd.data();
            writeSize = data.lcd.size();
            break;
        case ThumbnailType::MTH_ASTC:
            output = data.monthAstc.data();
            writeSize = data.monthAstc.size();
            break;
        case ThumbnailType::YEAR_ASTC:
            output = data.yearAstc.data();
            writeSize = data.yearAstc.size();
            break;
        default:
            return E_INVALID_ARGUMENTS;
    }
    if (writeSize <= 0) {
        return E_THUMBNAIL_LOCAL_CREATE_FAIL;
    }
    if (type == ThumbnailType::MTH_ASTC || type == ThumbnailType::YEAR_ASTC) {
        return SaveAstcDataToKvStore(data, type);
    }
    return SaveThumbDataToLocalDir(data, type, suffix, output, writeSize);
}

int ThumbnailUtils::SaveThumbDataToLocalDir(ThumbnailData &data,
    const ThumbnailType &type, const std::string &suffix, uint8_t *output, const int writeSize)
{
    string fileName;
    int ret = SaveFileCreateDir(data.path, suffix, fileName);
    if (ret != E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, ret},
            {KEY_OPT_FILE, fileName}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        MEDIA_ERR_LOG("SaveThumbDataToLocalDir create dir path %{public}s err %{public}d", data.path.c_str(), ret);
        return ret;
    }
    ret = ToSaveFile(data, type, fileName, output, writeSize);
    if (ret < 0) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, ret},
            {KEY_OPT_FILE, fileName}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        MEDIA_ERR_LOG("SaveThumbDataToLocalDir ToSaveFile path %{public}s err %{public}d", data.path.c_str(), ret);
        return ret;
    }
    return E_OK;
}

int32_t ThumbnailUtils::SetSource(shared_ptr<AVMetadataHelper> avMetadataHelper, const string &path)
{
    if (avMetadataHelper == nullptr) {
        MEDIA_ERR_LOG("avMetadataHelper == nullptr");
        return E_ERR;
    }
    MEDIA_DEBUG_LOG("path = %{private}s", path.c_str());
    int32_t fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("Open file failed, err %{public}d, file: %{public}s exists: %{public}d",
            errno, path.c_str(), MediaFileUtils::IsFileExists(path));
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, -errno},
            {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return E_ERR;
    }

    struct stat64 st;
    if (fstat64(fd, &st) != 0) {
        MEDIA_ERR_LOG("Get file state failed, err %{public}d", errno);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, -errno},
            {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        (void)close(fd);
        return E_ERR;
    }
    int64_t length = static_cast<int64_t>(st.st_size);
    int32_t ret = avMetadataHelper->SetSource(fd, 0, length, AV_META_USAGE_PIXEL_MAP);
    if (ret != 0) {
        DfxManager::GetInstance()->HandleThumbnailError(path, DfxType::AV_SET_SOURCE, ret);
        (void)close(fd);
        return E_ERR;
    }
    (void)close(fd);
    return SUCCESS;
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
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, static_cast<int32_t>(err)},
            {KEY_OPT_FILE, ""}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    tracer.Finish();

    tracer.Start("imageSource->CreatePixelMap");
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = size.width;
    decodeOpts.desiredSize.height = size.height;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    if (err != Media::SUCCESS) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, static_cast<int32_t>(err)},
            {KEY_OPT_FILE, ""}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        MEDIA_ERR_LOG("Failed to create pixelmap %{public}d", err);
        return false;
    }

    return true;
}

#ifdef DISTRIBUTED
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
        MEDIA_ERR_LOG("Failed to get key [%{private}s] ret [%{private}d]", key.c_str(), status);
        return false;
    }
    return true;
}
#endif

// notice: return value is whether thumb/lcd is deleted
bool ThumbnailUtils::DeleteOriginImage(ThumbRdbOpt &opts)
{
    ThumbnailData tmpData;
    tmpData.path = opts.path;
    bool isDelete = false;
    if (opts.path.empty()) {
        int err = 0;
        auto rdbSet = QueryThumbnailInfo(opts, tmpData, err);
        if (rdbSet == nullptr) {
            MEDIA_ERR_LOG("QueryThumbnailInfo Faild [ %{public}d ]", err);
            return isDelete;
        }
    }
    if (!opts.dateAdded.empty() && DeleteAstcDataFromKvStore(opts, ThumbnailType::MTH_ASTC)) {
        isDelete = true;
    }
    if (!opts.dateAdded.empty() && DeleteAstcDataFromKvStore(opts, ThumbnailType::YEAR_ASTC)) {
        isDelete = true;
    }
    if (DeleteThumbFile(tmpData, ThumbnailType::THUMB)) {
        isDelete = true;
    }
    if (ThumbnailUtils::IsSupportGenAstc() && DeleteThumbFile(tmpData, ThumbnailType::THUMB_ASTC)) {
        isDelete = true;
    }
    if (DeleteThumbFile(tmpData, ThumbnailType::LCD)) {
        isDelete = true;
    }
    string fileName = GetThumbnailPath(tmpData.path, "");
    return isDelete;
}

#ifdef DISTRIBUTED
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
        ret = true;
    }

    if (!ret) {
        if (!networkId.empty()) {
            MediaLibraryTracer tracer;
            tracer.Start("SyncPullKvstore");
            vector<string> keys = { key };
            auto syncStatus = MediaLibrarySyncOperation::SyncPullKvstore(kvStore, keys, networkId);
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
#endif

int64_t ThumbnailUtils::UTCTimeMilliSeconds()
{
    struct timespec t;
    constexpr int64_t SEC_TO_MSEC = 1e3;
    constexpr int64_t MSEC_TO_NSEC = 1e6;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * SEC_TO_MSEC + t.tv_nsec / MSEC_TO_NSEC;
}

bool ThumbnailUtils::CheckResultSetCount(const shared_ptr<ResultSet> &resultSet, int &err)
{
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }
    int rowCount = 0;
    err = resultSet->GetRowCount(rowCount);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get row count %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return false;
    }

    if (rowCount <= 0) {
        MEDIA_ERR_LOG("CheckCount No match!");
        err = E_EMPTY_VALUES_BUCKET;
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
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

void ThumbnailUtils::ParseQueryResult(const shared_ptr<ResultSet> &resultSet, ThumbnailData &data, int &err)
{
    int index;
    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.id, err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.path, err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_DATE_ADDED, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.dateAdded, err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_NAME, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.displayName, err);
    }

    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, index);
    if (err == NativeRdb::E_OK) {
        data.mediaType = MediaType::MEDIA_TYPE_ALL;
        err = resultSet->GetInt(index, data.mediaType);
    }
}

bool ThumbnailUtils::ResizeThumb(int &width, int &height)
{
    int maxLen = max(width, height);
    int minLen = min(width, height);
    if (minLen == 0) {
        MEDIA_ERR_LOG("Divisor minLen is 0");
        return false;
    }
    double ratio = static_cast<double>(maxLen) / minLen;
    if (minLen > SHORT_SIDE_THRESHOLD) {
        minLen = SHORT_SIDE_THRESHOLD;
        maxLen = static_cast<int>(SHORT_SIDE_THRESHOLD * ratio);
        if (maxLen > MAXIMUM_SHORT_SIDE_THRESHOLD) {
            maxLen = MAXIMUM_SHORT_SIDE_THRESHOLD;
        }
        if (height > width) {
            width = minLen;
            height = maxLen;
        } else {
            width = maxLen;
            height = minLen;
        }
    } else if (minLen <= SHORT_SIDE_THRESHOLD && maxLen > SHORT_SIDE_THRESHOLD) {
        if (ratio > ASPECT_RATIO_THRESHOLD) {
            int newMaxLen = static_cast<int>(minLen * ASPECT_RATIO_THRESHOLD);
            if (height > width) {
                width = minLen;
                height = newMaxLen;
            } else {
                width = newMaxLen;
                height = minLen;
            }
        }
    }
    return true;
}

bool ThumbnailUtils::ResizeLcd(int &width, int &height)
{
    int maxLen = max(width, height);
    int minLen = min(width, height);
    if (minLen == 0) {
        MEDIA_ERR_LOG("Divisor minLen is 0");
        return false;
    }
    double ratio = static_cast<double>(maxLen) / minLen;
    if (std::abs(ratio) < EPSILON) {
        MEDIA_ERR_LOG("ratio is 0");
        return false;
    }
    int newMaxLen = maxLen;
    int newMinLen = minLen;
    if (maxLen > LCD_LONG_SIDE_THRESHOLD) {
        newMaxLen = LCD_LONG_SIDE_THRESHOLD;
        newMinLen = static_cast<int>(newMaxLen / ratio);
    }
    int lastMinLen = newMinLen;
    int lastMaxLen = newMaxLen;
    if (newMinLen < LCD_SHORT_SIDE_THRESHOLD && minLen >= LCD_SHORT_SIDE_THRESHOLD) {
        lastMinLen = LCD_SHORT_SIDE_THRESHOLD;
        lastMaxLen = static_cast<int>(lastMinLen * ratio);
        if (lastMaxLen > MAXIMUM_LCD_LONG_SIDE) {
            lastMaxLen = MAXIMUM_LCD_LONG_SIDE;
            lastMinLen = static_cast<int>(lastMaxLen / ratio);
        }
    }
    if (height > width) {
        width = lastMinLen;
        height = lastMaxLen;
    } else {
        width = lastMaxLen;
        height = lastMinLen;
    }
    return true;
}

bool ThumbnailUtils::IsSupportGenAstc()
{
    return ImageSource::IsSupportGenAstc();
}

int ThumbnailUtils::SaveAstcDataToKvStore(ThumbnailData &data, const ThumbnailType &type)
{
    string key;
    if (!GenerateKvStoreKey(data.id, data.dateAdded, key)) {
        MEDIA_ERR_LOG("GenerateKvStoreKey failed");
        return E_ERR;
    }

    std::shared_ptr<MediaLibraryKvStore> kvStore;
    if (type == ThumbnailType::MTH_ASTC) {
        kvStore = MediaLibraryKvStoreManager::GetInstance()
            .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC);
    } else if (type == ThumbnailType::YEAR_ASTC) {
        kvStore = MediaLibraryKvStoreManager::GetInstance()
            .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::YEAR_ASTC);
    } else {
        MEDIA_ERR_LOG("invalid thumbnailType");
        return E_ERR;
    }
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("kvStore is nullptr");
        return E_ERR;
    }

    int status = kvStore->Insert(key, type == ThumbnailType::MTH_ASTC ? data.monthAstc : data.yearAstc);
    MEDIA_INFO_LOG("type:%{public}d, field_id:%{public}s, status:%{public}d", type, key.c_str(), status);
    return status;
}

bool ThumbnailUtils::GenerateKvStoreKey(const std::string &fieldId, const std::string &dateAdded, std::string &key)
{
    if (fieldId.empty()) {
        MEDIA_ERR_LOG("fieldId is empty");
        return false;
    }
    if (dateAdded.empty()) {
        MEDIA_ERR_LOG("dateAdded is empty");
        return false;
    }

    size_t length = fieldId.length();
    if (length >= MAX_FIELD_LENGTH) {
        MEDIA_ERR_LOG("fieldId too long");
        return false;
    }
    std::string assembledFieldId = KVSTORE_FIELD_ID_TEMPLATE.substr(length) + fieldId;

    length = dateAdded.length();
    std::string assembledDateAdded;
    if (length > MAX_DATE_ADDED_LENGTH) {
        MEDIA_ERR_LOG("dateAdded invalid, fieldId:%{public}s", fieldId.c_str());
        return false;
    } else if (length == MAX_DATE_ADDED_LENGTH) {
        assembledDateAdded = dateAdded;
    } else {
        assembledDateAdded = KVSTORE_DATE_ADDED_TEMPLATE.substr(length) + dateAdded;
    }
    key = assembledDateAdded.substr(0, MAX_TIMEID_LENGTH) + assembledFieldId;
    return true;
}

bool ThumbnailUtils::CheckDateAdded(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (!data.dateAdded.empty()) {
        return true;
    }

    vector<string> column = {
        MEDIA_DATA_DB_DATE_ADDED,
    };
    vector<string> selectionArgs;
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + data.id;
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.SetWhereClause(strQueryCondition);
    rdbPredicates.SetWhereArgs(selectionArgs);
    shared_ptr<ResultSet> resultSet = opts.store->QueryByStep(rdbPredicates, column);

    int err;
    if (!CheckResultSetCount(resultSet, err)) {
        MEDIA_ERR_LOG("CheckResultSetCount failed, err: %{public}d", err);
        return false;
    }
    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_ERR_LOG("GoToFirstRow failed, err: %{public}d", err);
        return false;
    }

    int index;
    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_DATE_ADDED, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.dateAdded, err);
    } else {
        MEDIA_ERR_LOG("GetColumnIndex failed, err: %{public}d", err);
        resultSet->Close();
        return false;
    }
    resultSet->Close();
    return true;
}

void ThumbnailUtils::QueryThumbnailDataFromFileId(ThumbRdbOpt &opts, const std::string &id,
    ThumbnailData &data, int &err)
{
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, id);
    vector<string> columns = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_FILE_PATH,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_DATE_ADDED,
    };
    auto resultSet = opts.store->QueryByStep(predicates, columns);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return;
    }
    err = resultSet->GoToFirstRow();
    if (err != NativeRdb::E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        resultSet->Close();
        return;
    }

    ParseQueryResult(resultSet, data, err);

    int index;
    err = resultSet->GetColumnIndex(MEDIA_DATA_DB_DATE_ADDED, index);
    if (err == NativeRdb::E_OK) {
        ParseStringResult(resultSet, index, data.dateAdded, err);
    }

    if (err != NativeRdb::E_OK || data.path.empty()) {
        MEDIA_ERR_LOG("Fail to query thumbnail data using id: %{public}s, err: %{public}d", id.c_str(), err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        resultSet->Close();
        return;
    }
    resultSet->Close();
}

bool ThumbnailUtils::DeleteAstcDataFromKvStore(ThumbRdbOpt &opts, const ThumbnailType &type)
{
    string key;
    if (!GenerateKvStoreKey(opts.row, opts.dateAdded, key)) {
        MEDIA_ERR_LOG("GenerateKvStoreKey failed");
        return false;
    }

    std::shared_ptr<MediaLibraryKvStore> kvStore;
    if (type == ThumbnailType::MTH_ASTC) {
        kvStore = MediaLibraryKvStoreManager::GetInstance()
            .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC);
    } else if (type == ThumbnailType::YEAR_ASTC) {
        kvStore = MediaLibraryKvStoreManager::GetInstance()
            .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::YEAR_ASTC);
    } else {
        MEDIA_ERR_LOG("invalid thumbnailType");
        return false;
    }
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("kvStore is nullptr");
        return false;
    }

    int status = kvStore->Delete(key);
    return status == E_OK;
}

void ThumbnailUtils::GetThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &outData)
{
    if (opts.store == nullptr) {
        return;
    }
    if (!opts.path.empty()) {
        outData.path = opts.path;
        outData.id = opts.row;
        outData.dateAdded = opts.dateAdded;
        outData.fileUri = opts.fileUri;
        outData.stats.uri = outData.fileUri;
        return;
    }
    string filesTableName = opts.table;
    int errCode = E_ERR;
    if (!opts.networkId.empty()) {
        filesTableName = opts.store->ObtainDistributedTableName(opts.networkId, opts.table, errCode);
    }
    if (filesTableName.empty()) {
        return;
    }
    opts.table = filesTableName;
    int err;
    ThumbnailUtils::QueryThumbnailInfo(opts, outData, err);
    if (err != E_OK) {
        MEDIA_ERR_LOG("query fail [%{public}d]", err);
    }
}

bool ThumbnailUtils::ScaleThumbnailEx(ThumbnailData &data)
{
    if (data.source == nullptr) {
        MEDIA_ERR_LOG("Fail to scale thumbnail, data source is empty.");
        return false;
    }
    Size desiredSize;
    Size targetSize = ConvertDecodeSize(data, {data.source->GetWidth(), data.source->GetHeight()}, desiredSize);
    if (!ScaleTargetPixelMap(data, targetSize)) {
        MEDIA_ERR_LOG("Fail to scale to targetSize");
        return false;
    }
    MediaLibraryTracer tracer;
    tracer.Start("CenterScale");
    PostProc postProc;
    if (!postProc.CenterScale(desiredSize, *data.source)) {
        MEDIA_ERR_LOG("thumbnail center crop failed, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    return true;
}

void ThumbnailUtils::RecordStartGenerateStats(ThumbnailData::GenerateStats &stats,
    GenerateScene scene, LoadSourceType sourceType)
{
    stats.startTime = MediaFileUtils::UTCTimeMilliSeconds();
    stats.scene = scene;
    stats.sourceType = sourceType;
}

void ThumbnailUtils::RecordCostTimeAndReport(ThumbnailData::GenerateStats &stats)
{
    stats.totalCost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - stats.startTime);
    DfxManager::GetInstance()->HandleThumbnailGeneration(stats);
}

} // namespace Media
} // namespace OHOS
