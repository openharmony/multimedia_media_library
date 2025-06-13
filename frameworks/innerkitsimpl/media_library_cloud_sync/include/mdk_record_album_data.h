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

#ifndef OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_ALBUM_DATA_H
#define OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_ALBUM_DATA_H

#include <map>
#include <vector>
#include <iostream>
#include <sstream>

#include "mdk_record.h"
#include "mdk_reference.h"
#include "mdk_database.h"
#include "mdk_record_reader.h"
#include "mdk_record_field.h"

namespace OHOS::Media::CloudSync {
class MDKRecordAlbumData {
private:  // data member
    MDKRecord record_;
    std::map<std::string, MDKRecordField> fields_;
    std::map<std::string, MDKRecordField> properties_;

private:  // composited class
    MDKRecordReader recordReader_;

public:  // constructor & destructor
    MDKRecordAlbumData() = default;
    MDKRecordAlbumData(const MDKRecord &record)
    {
        this->UnMarshalling(record);
    }
    virtual ~MDKRecordAlbumData() = default;

public:  // Marshalling & UnMarshalling
    void UnMarshalling(const MDKRecord &record)
    {
        this->record_ = record;
        this->record_.GetRecordData(this->fields_);
        if (this->fields_.find(this->KEY_PROPERTIES) != this->fields_.end()) {
            this->fields_[this->KEY_PROPERTIES].GetRecordMap(this->properties_);
        }
        this->record_.SetRecordData(this->fields_);
    }
    void Marshalling()
    {
        if (this->properties_.size() > 0) {
            this->fields_[this->KEY_PROPERTIES] = MDKRecordField(this->properties_);
        }
        this->record_.SetRecordData(this->fields_);
        this->record_.SetRecordType(this->VALUE_RECORD_TYPE);
    }

public:  // getter & setter
    MDKRecord GetDKRecord()
    {
        this->record_.SetRecordData(this->fields_);
        return this->record_;
    }
    void SetDKRecord(MDKRecord &record)
    {
        this->record_ = record;
        record.GetRecordData(this->fields_);
    }
    std::optional<std::string> GetBundleName()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, this->ALBUM_BUNDLE_NAME);
    }
    void SetBundleName(const std::string &bundleName)
    {
        this->properties_[this->ALBUM_BUNDLE_NAME] = MDKRecordField(bundleName);
    }
    std::optional<std::string> GetAlbumName()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, this->ALBUM_NAME);
    }
    void SetAlbumName(const std::string &albumName)
    {
        this->fields_[this->ALBUM_NAME] = MDKRecordField(albumName);
    }
    std::optional<std::string> GetlPath()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, this->ALBUM_LOCAL_PATH);
    }
    void SetlPath(const std::string &path)
    {
        this->fields_[this->ALBUM_LOCAL_PATH] = MDKRecordField(path);
    }
    std::optional<int32_t> GetAlbumType()  const
    {
        std::optional<std::string> albumTypeStr =
            this->recordReader_.GetStringValue(this->properties_, this->ALBUM_TYPE);
        if (albumTypeStr.has_value()) {
            std::stringstream ss(albumTypeStr.value());
            int32_t result = 0;
            if (ss >> result) {
                return result;
            }
        }
        return 0;
    }
    void SetAlbumType(const int32_t &albumType)
    {
        this->properties_[this->ALBUM_TYPE] = MDKRecordField(albumType);
    }
    std::optional<int32_t> GetAlbumSubType()  const
    {
        std::optional<std::string> albumSubTypeStr = this->recordReader_.GetStringValue(this->properties_,
            this->ALBUM_SUBTYPE);
        if (albumSubTypeStr.has_value()) {
            std::stringstream ss(albumSubTypeStr.value());
            int32_t result = 0;
            if (ss >> result) {
                return result;
            }
        }
        return 0;
    }
    void SetAlbumSubType(const int32_t &albumSubType)
    {
        this->properties_[this->ALBUM_SUBTYPE] = MDKRecordField(albumSubType);
    }
    std::optional<int64_t> GetDateAdded()  const
    {
        std::optional<std::string> strOpt = this->recordReader_.GetStringValue(this->properties_,
            this->ALBUM_DATE_ADDED);
        if (strOpt.has_value()) {
            std::stringstream ss(strOpt.value());
            int64_t result = 0;
            if (ss >> result) {
                return result;
            }
        }
        return 0;
    }
    void SetDateAdded(const int64_t &dateAdded)
    {
        this->properties_[this->ALBUM_DATE_ADDED] = MDKRecordField(dateAdded);
    }
    std::optional<int64_t> GetDateModified()  const
    {
        std::optional<std::string> strOpt = this->recordReader_.GetStringValue(this->properties_,
            this->ALBUM_DATE_MODIFIED);
        if (strOpt.has_value()) {
            std::stringstream ss(strOpt.value());
            int64_t result = 0;
            if (ss >> result) {
                return result;
            }
        }
        return 0;
    }
    void SetDateModified(const int64_t &dateModified)
    {
        this->properties_[this->ALBUM_DATE_MODIFIED] = MDKRecordField(dateModified);
    }
    // albumId in DKRecord, means cloud_id in album table.
    std::optional<std::string> GetCloudId()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, this->ALBUM_ID);
    }
    void SetCloudId(const std::string &albumId)
    {
        this->fields_[this->ALBUM_ID] = MDKRecordField(albumId);
    }
    std::optional<int32_t> GetLogicType()  const
    {
        return this->recordReader_.GetIntValue(this->fields_, this->ALBUM_LOGIC_TYPE);
    }
    // locgicType, 0 - Physical, 1 - Logical
    void SetLogicType(const int32_t &logicType)
    {
        this->fields_[this->ALBUM_LOGIC_TYPE] = MDKRecordField(logicType);
    }
    std::optional<bool> IsLogic()  const
    {
        return this->recordReader_.GetBoolValue(this->fields_, this->ALBUM_IS_LOGIC);
    }
    void SetIsLogic(const bool &isLogic)
    {
        this->fields_[this->ALBUM_IS_LOGIC] = MDKRecordField(isLogic);
    }
    std::optional<std::string> GetType()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, this->KEY_TYPE);
    }
    // type, "directory" or "file"
    void SetType(const std::string &type)
    {
        this->fields_[this->KEY_TYPE] = MDKRecordField(type);
    }
    std::optional<std::string> GetLocalLanguage()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, this->ALBUM_LOCAL_LANGUAGE);
    }
    void SetLocalLanguage(const std::string &localLanguage)
    {
        this->properties_[this->ALBUM_LOCAL_LANGUAGE] = MDKRecordField(localLanguage);
    }
    void SetNewCreate(const bool &isNewCreate)
    {
        this->record_.SetNewCreate(isNewCreate);
    }
    bool GetNewCreate()  const
    {
        return this->record_.GetNewCreate();
    }
    std::string GetRecordId()  const
    {
        return this->record_.GetRecordId();
    }
    void SetRecordId(std::string recordId)
    {
        this->record_.SetRecordId(recordId);
    }
    std::optional<std::string> GetEmptyShow()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, this->ALBUM_EMPTY_SHOW);
    }
    // emptyShow = "1", when recordId = default-album-4, which is hidden album.
    void SetEmptyShow(const std::string &emptyShow)
    {
        this->properties_[this->ALBUM_EMPTY_SHOW] = MDKRecordField(emptyShow);
    }
    std::optional<int32_t> GetAlbumOrder()  const
    {
        return this->recordReader_.GetIntValue(this->fields_, this->ALBUM_ORDER);
    }
    void SetAlbumOrder(const int32_t &albumOrder)
    {
        this->fields_[this->ALBUM_ORDER] = MDKRecordField(albumOrder);
    }
    std::optional<int32_t> GetPriority()  const
    {
        return this->recordReader_.GetIntValue(this->fields_, this->ALBUM_PRIORITY);
    }
    void SetPriority(const int32_t &priority)
    {
        this->fields_[this->ALBUM_PRIORITY] = MDKRecordField(priority);
    }

private:
    const std::string VALUE_RECORD_TYPE = "album";
    /* basic */
    const std::string ALBUM_ID = "albumId";
    const std::string ALBUM_LOGIC_TYPE = "logicType";
    const std::string ALBUM_LOCAL_PATH = "localPath";
    const std::string ALBUM_IS_LOGIC = "isLogic";
    const std::string KEY_TYPE = "type";
    const std::string KEY_PROPERTIES = "properties";

    /* properties */
    const std::string ALBUM_BUNDLE_NAME = "bundle_name";
    const std::string ALBUM_NAME = "albumName";
    const std::string ALBUM_EMPTY_SHOW = "emptyShow";
    const std::string ALBUM_TYPE = "album_type";
    const std::string ALBUM_SUBTYPE = "album_subtype";
    const std::string ALBUM_DATE_ADDED = "date_added";
    const std::string ALBUM_DATE_MODIFIED = "date_modified";
    const std::string ALBUM_LOCAL_LANGUAGE = "local_language";
    const std::string ALBUM_ORDER = "album_order";
    const std::string ALBUM_PRIORITY = "priority";
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_ALBUM_DATA_H