/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import { PickerColorMode } from '@ohos.file.PhotoPickerComponent';

@Component
export struct AlbumPickerComponent {
  albumPickerOptions?: AlbumPickerOptions | undefined;
  onAlbumClick?: (albumInfo: AlbumInfo) => boolean;

  build() {
    Row() {
      Column() {
        SecurityUIExtensionComponent({
          parameters: {
            "ability.want.params.uiExtensionTargetType":"photoPicker",
            targetPage: "albumPage",
            themeColorMode: this.albumPickerOptions?.themeColorMode,
          }
        }).height('100%').width('100%').onRemoteReady((proxy) => {
          console.info('AlbumPickerComponent onRemoteReady');
        }).onReceive((data) => {
          let wantParam: Record<string, Object> = data as Record<string, Object>;
          let dataType = wantParam['dataType'] as string;
          if (dataType === 'selectAlbum') {
            if (this.onAlbumClick) {
              let albumInfo: AlbumInfo = new AlbumInfo();
              albumInfo.uri = wantParam['albumUri'] as string;
              this.onAlbumClick(albumInfo);
            }
          }
          console.info('AlbumPickerComponent onReceive ' + dataType);
        }).onError(() => {
          console.info('AlbumPickerComponent onError');
        });
      }
      .width('100%')
    }
    .height('100%')
  }
}

export class AlbumPickerOptions {
  themeColorMode?: PickerColorMode;
}

export class AlbumInfo {
  uri?: string;
}