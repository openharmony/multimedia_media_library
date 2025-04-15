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

#ifndef TDD_CSV_FILE_READER_H
#define TDD_CSV_FILE_READER_H

#include <string>
#include <vector>
#include <fstream>
#include <numeric>

#include "gtest/gtest.h"
#include "media_log.h"

namespace OHOS::Media::TestUtils {
class CSVRowData {
private:
    std::vector<std::string> fields_;

public:
    void SetFields(const std::vector<std::string> fields)
    {
        this->fields_ = fields;
    }
    std::string GetString(int32_t index) const
    {
        if (index < 0 || index >= fields_.size()) {
            return "";
        }
        std::string result = fields_[index];
        return result;
    }
};
class CSVFileReader {
public:
    enum {
        E_OK,
        E_OPEN_FILE_FAILED,
    };

private:
    std::vector<std::string> headerNames_;
    std::vector<CSVRowData> rows_;
    int32_t currentRowIndex_ = 0;
    std::string csvFilePath_;
    char EMPTY_SPACE = ' ';

public:  // constructor & destructor
    CSVFileReader() = default;
    CSVFileReader(const std::string &csvFilePath) : csvFilePath_(csvFilePath)
    {}

public:  // getter & setter
    std::vector<std::string> GetHeaderNames() const
    {
        return this->headerNames_;
    }

    std::vector<CSVRowData> GetRows() const
    {
        return this->rows_;
    }

public:
    bool HasNext(CSVRowData &row)
    {
        if (this->currentRowIndex_ >= this->rows_.size()) {
            return false;
        }
        row = this->rows_[this->currentRowIndex_];
        this->currentRowIndex_++;
        return true;
    }
    std::string GetString(const CSVRowData &row, const std::string headerName)
    {
        auto it = std::find(this->headerNames_.begin(), this->headerNames_.end(), headerName);
        int32_t index = -1;
        if (it != this->headerNames_.end()) {
            index = it - this->headerNames_.begin();
        } else {
            return "";
        }
        std::string value = row.GetString(index);
        return value;
    }
    int32_t GetInt(const CSVRowData &row, const std::string headerName)
    {
        std::string value = this->GetString(row, headerName);
        // replace escape characters
        if (!value.empty() && value.front() == this->EMPTY_SPACE) {
            value.erase(0, value.find_first_not_of(this->EMPTY_SPACE));
        }
        if (!value.empty() && value.back() == this->EMPTY_SPACE) {
            value.erase(value.find_last_not_of(this->EMPTY_SPACE) + 1);
        }
        if (value.empty()) {
            return 0;
        }
        return std::stoi(value);
    }
    int64_t GetLong(const CSVRowData &row, const std::string headerName)
    {
        std::string value = this->GetString(row, headerName);
        if (value.empty()) {
            return 0;
        }
        // replace escape characters
        if (!value.empty() && value.front() == this->EMPTY_SPACE) {
            value.erase(0, value.find_first_not_of(this->EMPTY_SPACE));
        }
        if (!value.empty() && value.back() == this->EMPTY_SPACE) {
            value.erase(value.find_last_not_of(this->EMPTY_SPACE) + 1);
        }
        if (value.empty()) {
            return 0;
        }
        return std::stol(value);
    }
    int32_t ReadCSVFile()
    {
        return this->ReadCSVFile(this->csvFilePath_);
    }

private:
    int32_t ReadCSVFile(const std::string &filename)
    {
        // reset
        this->headerNames_.clear();
        this->rows_.clear();
        // open file
        std::ifstream file(filename);
        if (!file.is_open()) {
            GTEST_LOG_(INFO) << "Failed to open file: %{public}s" << filename;
            return E_OPEN_FILE_FAILED;
        }
        // read data
        std::string line;
        const int32_t headerRowIndex = 15;
        int index = 0;
        while (std::getline(file, line)) {
            index++;
            if (line.empty() || index < headerRowIndex) {
                continue;
            }
            std::vector<std::string> fields = ReadFields(line);
            if (index == headerRowIndex) {
                this->headerNames_ = fields;
                continue;
            }
            CSVRowData rowData;
            rowData.SetFields(fields);
            this->rows_.emplace_back(rowData);
        }
        file.close();
        return E_OK;
    }

    std::string ToString(const std::vector<std::string> &values)
    {
        std::vector<std::string> result;
        for (auto &value : values) {
            result.emplace_back(value + ", ");
        }
        return std::accumulate(result.begin(), result.end(), std::string());
    }
    std::vector<std::string> ReadFields(const std::string line)
    {
        std::vector<std::string> parts;
        if (line.empty()) {
            return parts;
        }

        std::stringstream ss(line);
        std::string part;
        while (std::getline(ss, part, ',')) {
            parts.push_back(part);
        }
        return parts;
    }
};
}  // namespace OHOS::Media::TestUtils
#endif  // TDD_CSV_FILE_READER_H