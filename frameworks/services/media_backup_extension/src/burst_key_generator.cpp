/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
 
#include "burst_key_generator.h"
 
#include <uuid.h>
 
#include "media_log.h"
 
namespace OHOS {
namespace Media {
/**
 * @brief find prefix contains "_BURST" of fileInfo.title
 *
 * @param fileInfo row data from gallery.db # gallery_media
 * @return std::string prefix of fileInfo.title
 */
std::string BurstKeyGenerator::FindTitlePrefix(const FileInfo &fileInfo)
{
    auto suffixIndex = fileInfo.title.find(TITLE_KEY_WORDS_OF_BURST);
    if (suffixIndex == std::string::npos) {
        return "";
    }
    return fileInfo.title.substr(0, suffixIndex + TITLE_KEY_WORDS_OF_BURST.size());
}
 
/**
 * @brief find group hash based on fileInfo.relativeBucketId, fileInfo.title and groupIndex
 *
 * @param fileInfo row data from gallery.db # gallery_media
 * @return std::string hash to identify a group of burst photo
 */
std::string BurstKeyGenerator::FindGroupHash(const FileInfo &fileInfo)
{
    return fileInfo.relativeBucketId + "#" + FindTitlePrefix(fileInfo) + "#" + std::to_string(FindGroupIndex(fileInfo));
}
 
/**
 * @brief find groupIndex based on objectHash
 *
 * @param fileInfo row data from gallery.db # gallery_media
 * @return int32_t groupIndex to identify which group the fileInfo belongs to
 */
int32_t BurstKeyGenerator::FindGroupIndex(const FileInfo &fileInfo)
{
    // the photo do not in recycle bin.
    if (fileInfo.recycleFlag == 0) {
        return 0;
    }
    std::string objectHash = FindObjectHash(fileInfo);
    auto it = objectHashMap_.find(objectHash);
    int32_t groupIndex = 1;
    if (it != objectHashMap_.end()) {
        groupIndex = it->second + 1;
    }
    objectHashMap_[objectHash] = groupIndex;
    return groupIndex;
}
 
/**
 * @brief find objectHash based on fileInfo.relativeBucketId, fileInfo.title and fileInfo.hashCode
 *
 * @param fileInfo row data from gallery.db # gallery_media
 * @return std::string objectHash to identify fileInfo
 */
std::string BurstKeyGenerator::FindObjectHash(const FileInfo &fileInfo)
{
    return fileInfo.relativeBucketId + "#" + FindTitlePrefix(fileInfo) + "#" + fileInfo.hashCode;
}
 
/**
 * @brief generate a uuid, like xxxxxxxx-xxxx-xxxx-xxxxxxxx-xxxx
 *
 * @return std::string uuid with 36 characters
 */
std::string BurstKeyGenerator::GenerateUuid()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[37] = {};
    uuid_unparse(uuid, str);
    return str;
}
 
/**
 * @brief find burstKey for burst photo in Album and Recycle-Bin
 *
 * @param fileInfo row data from gallery.db # gallery_media
 * @return std::string burstKey to identify burst photo group
 */
std::string BurstKeyGenerator::FindBurstKey(const FileInfo &fileInfo)
{
    // isBurst, 1=burst cover photo, 2=burst photo, 0=others
    if (fileInfo.isBurst != BURST_COVER_TYPE && fileInfo.isBurst != BURST_MEMBER_TYPE) {
        return "";
    }
    std::string groupHash = FindGroupHash(fileInfo);
    auto it = groupHashMap_.find(groupHash);
    if (it == groupHashMap_.end()) {
        groupHashMap_[groupHash] = GenerateUuid();
    }
    MEDIA_INFO_LOG("burst photo, objectHash: %{public}s, groupHash: %{public}s, burstKey: %{public}s",
        FindObjectHash(fileInfo).c_str(), groupHash.c_str(), groupHashMap_[groupHash].c_str());
    return groupHashMap_[groupHash];
}

/**
 * parse burst sequence from FileInfo.title
 *
 * @param fileInfo the data from gallery.db#gallery_media
 * @return the burst sequence, if not burst photo return 0.
 */
int32_t BurstKeyGenerator::FindBurstSequence(const FileInfo &fileInfo)
{
    // only accept data of burst photo
    if (fileInfo.isBurst != BURST_COVER_TYPE && fileInfo.isBurst != BURST_MEMBER_TYPE) {
        return 0;
    }
    std::string title = fileInfo.title;
    // title must contains _BURST
    size_t pos = title.find(TITLE_KEY_WORDS_OF_BURST);
    if (pos == std::string::npos) {
        return 0;
    }
    // avoid crash for invalid data: out of range
    int numberStartIndex = pos + TITLE_KEY_WORDS_OF_BURST.size();
    int minLen = numberStartIndex + TITLE_SEQUENCE_LEN_OF_BURST;
    if (minLen > title.size()) {
        return 0;
    }
    std::string number = title.substr(numberStartIndex, TITLE_SEQUENCE_LEN_OF_BURST);
    // avoid crash for invalid data: not number sequence
    if (!isNumeric(number)) {
        return 0;
    }
    return std::stoi(number);
}
}  // namespace Media
}  // namespace OHOS