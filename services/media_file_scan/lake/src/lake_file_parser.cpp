/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#define MLOG_TAG "LakeFileParser"

#include "lake_file_parser.h"

#include "file_scan_utils.h"
#include "media_file_utils.h"

using namespace OHOS::NativeRdb;
namespace OHOS::Media {

std::atomic<uint32_t> LakeFileParser::imageNumber_{0};
std::atomic<uint32_t> LakeFileParser::videoNumber_{0};

LakeFileParser::LakeFileParser(const std::string &path, ScanMode scanMode)
    : FileParser(path, FileSourceType::MEDIA_HO_LAKE, scanMode)
{
    ParseFileInfo();
    MEDIA_INFO_LOG("LakeFileParser: The info is %{public}s", PrintInfo(fileInfo_).c_str());
}

LakeFileParser::LakeFileParser(const MediaNotifyInfo &notifyInfo, ScanMode scanMode)
    : FileParser(notifyInfo, FileSourceType::MEDIA_HO_LAKE, scanMode)
{
    ParseFileInfo();
    MEDIA_INFO_LOG("LakeFileParser: The info is %{public}s", PrintInfo(fileInfo_).c_str());
}
// 返回当前数据是插入还是更新，还是不进行任何操作
// 包含判定是否有重复文件，以及判断重复文件是否有变更
FileUpdateType LakeFileParser::GetFileUpdateType()
{
    if (!IsNotifyInfoValid()) {
        MEDIA_ERR_LOG("Invalid lake notifyInfo obj: %{public}d, opt: %{public}d, isBeforePathEmpty: %{public}d, "
            "isAfterPathEmpty: %{public}d",
            static_cast<int32_t>(notifyInfo_.objType), static_cast<int32_t>(notifyInfo_.optType),
            notifyInfo_.beforePath.empty(), notifyInfo_.afterPath.empty());
        return FileUpdateType::NO_CHANGE;
    }
    FileParser::PhotosRowData rowData = FindSameFile();
    if (!rowData.IsExist()) {
        updateType_ = FileUpdateType::INSERT;
    } else {
        SetByPhotosRowData(rowData);
        if (HasChangePart(rowData)) {
            updateType_ = IsStoragePathChanged(rowData) ? FileUpdateType::UPDATE_ALBUM : FileUpdateType::UPDATE;
        } else {
            updateType_ = FileUpdateType::NO_CHANGE;
        }
    }
    MEDIA_INFO_LOG("lake file updateType: %{public}d, fileInfo: %{public}s", static_cast<int32_t>(updateType_),
        ToString().c_str());
    return updateType_;
}

// 桶目录修改
void LakeFileParser::SetCloudPath()
{
    std::string cloudPath;
    int32_t uniqueId = GetUniqueId();
    int32_t errCode = FileScanUtils::CreateAssetPathById(
        uniqueId, fileInfo_.fileType, MediaFileUtils::GetExtensionFromPath(fileInfo_.displayName), cloudPath);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("FileParser: Lake CreateAssetPathById failed, errCode: %{public}d, fileInfo: %{public}s",
            errCode, ToString().c_str());
        fileInfo_.needInsert = false;
        return;
    }
    fileInfo_.cloudPath = cloudPath;
}

int32_t LakeFileParser::GetUniqueId()
{
    int32_t uniqueId = 0;
    switch (fileInfo_.fileType) {
        case static_cast<int32_t>(OuterMediaType::PICTURE): {
            uniqueId = static_cast<int32_t>(imageNumber_.fetch_add(1));
            break;
        }
        case static_cast<int32_t>(OuterMediaType::VIDEO): {
            uniqueId = static_cast<int32_t>(videoNumber_.fetch_add(1));
            break;
        }
        default:
            MEDIA_ERR_LOG("FileParser: Unsupported file type: %{public}d", fileInfo_.fileType);
    }
    return uniqueId;
}

void LakeFileParser::SetSubtypeFromMetadata(std::unique_ptr<Metadata> &data)
{
    if (data->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::SPATIAL_3DGS) ||
        data->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::SLOW_MOTION_VIDEO)) {
        fileInfo_.subtype = data->GetPhotoSubType();
    }
}
// LCOV_EXCL_STOP
}  // namespace OHOS::Media