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

import photoAccessHelper from '@ohos.file.photoAccessHelper';
const FILTER_MEDIA_TYPE_ALL = 'FILTER_MEDIA_TYPE_ALL';
const FILTER_MEDIA_TYPE_IMAGE = 'FILTER_MEDIA_TYPE_IMAGE';
const FILTER_MEDIA_TYPE_VIDEO = 'FILTER_MEDIA_TYPE_VIDEO';

@Component
export struct PhotoPickerComponent {
  pickerOptions?: PickerOptions | undefined;
  onSelect?: (uri: string) => void;
  onDeselect?: (uri: string) => void;
  onItemClicked?: (itemInfo: ItemInfo, clickType: ClickType) => boolean;
  onEnterPhotoBrowser?: (photoBrowserInfo: PhotoBrowserInfo) => boolean;
  onExitPhotoBrowser?: (photoBrowserInfo: PhotoBrowserInfo) => boolean;
  onPickerControllerReady?: () => void;
  onPhotoBrowserChanged?: (browserItemInfo: BaseItemInfo) => boolean;
  @ObjectLink @Watch('onChanged') pickerController: PickerController;
  private proxy: UIExtensionProxy | undefined;

  private onChanged(): void {
    if (!this.proxy) {
      return;
    }
    let data = this.pickerController?.data;
    if (data?.has('SET_SELECTED_URIS')) {
      this.proxy.send({'selectUris': data?.get('SET_SELECTED_URIS') as Array<string>});
      console.info('PhotoPickerComponent onChanged: SET_SELECTED_URIS');
    } else if (data?.has('SET_ALBUM_URI')) {
      this.proxy.send({'albumUri': data?.get('SET_ALBUM_URI') as string});
      console.info('PhotoPickerComponent onChanged: SET_ALBUM_URI');
    } else if (data?.has('SET_MAX_SELECT_COUNT')) {
      let maxSelected: MaxSelected = data?.get('SET_MAX_SELECT_COUNT') as MaxSelected;
      let map: Map<MaxCountType, number> | undefined = maxSelected?.data;
      this.proxy.send({'totalCount': map?.get(MaxCountType.TOTAL_MAX_COUNT),
        'photoCount': map?.get(MaxCountType.PHOTO_MAX_COUNT), 'videoCount': map?.get(MaxCountType.VIDEO_MAX_COUNT)});
      console.info('PhotoPickerComponent onChanged: SET_MAX_SELECT_COUNT');
    } else if (data?.has('SET_PHOTO_BROWSER_ITEM')) {
      this.proxy.send({'itemUri': data?.get('SET_PHOTO_BROWSER_ITEM') as string});
      console.info('PhotoPickerComponent onChanged: SET_PHOTO_BROWSER_ITEM');
    } else {
      console.info('PhotoPickerComponent onChanged: other case');
    }
  }

  build() {
    Row() {
      Column() {
        SecurityUIExtensionComponent({
          parameters: {
            "ability.want.params.uiExtensionTargetType":"photoPicker",
            uri: "multipleselect",
            targetPage: "photoPage",
            filterMediaType: this.convertMIMETypeToFilterType(this.pickerOptions?.MIMEType),
            maxSelectNumber: this.pickerOptions?.maxSelectNumber as number,
            isPhotoTakingSupported: this.pickerOptions?.isPhotoTakingSupported as boolean,
            isEditSupported: false,
            recommendationOptions: this.pickerOptions?.recommendationOptions as photoAccessHelper.RecommendationOptions,
            preselectedUri: this.pickerOptions?.preselectedUris as Array<string>,
            isFromPickerView: true,
            isNeedActionBar: false,
            isNeedSelectBar: false,
            isSearchSupported: this.pickerOptions?.isSearchSupported as boolean,
            checkBoxColor: this.pickerOptions?.checkBoxColor as string,
            backgroundColor: this.pickerOptions?.backgroundColor as string,
            checkboxTextColor: this.pickerOptions?.checkboxTextColor as string,
            photoBrowserBackgroundColorMode: this.pickerOptions?.photoBrowserBackgroundColorMode as PickerColorMode,
            isRepeatSelectSupported: this.pickerOptions?.isRepeatSelectSupported as boolean,
            maxSelectedReminderMode: this.pickerOptions?.maxSelectedReminderMode as ReminderMode,
            orientation: this.pickerOptions?.orientation as PickerOrientation,
            selectMode: this.pickerOptions?.selectMode as SelectMode,
            maxPhotoSelectNumber: this.pickerOptions?.maxPhotoSelectNumber as number,
            maxVideoSelectNumber: this.pickerOptions?.maxVideoSelectNumber as number,
            isOnItemClickedSet: this.onItemClicked? true : false,
            isPreviewForSingleSelectionSupported: this.pickerOptions?.isPreviewForSingleSelectionSupported as boolean
          }
        }).height('100%').width('100%').onRemoteReady((proxy) => {
          this.proxy = proxy;
          console.info('PhotoPickerComponent onRemoteReady');
        }).onReceive((data) => {
          let wantParam: Record<string, Object> = data as Record<string, Object>;
          this.handleOnReceive(wantParam);
        }).onError(() => {
          console.info('PhotoPickerComponent onError');
        });
      }
      .width('100%')
    }
    .height('100%')
  }

  private handleOnReceive(wantParam: Record<string, Object>): void {
    let dataType = wantParam['dataType'] as string;
    console.info('PhotoPickerComponent onReceive: dataType = ' + dataType);
    if (dataType === 'selectOrDeselect') {
      this.handleSelectOrDeselect(wantParam);
    } else if (dataType === 'itemClick') {
      this.handleItemClick(wantParam);
    } else if (dataType === 'onPhotoBrowserStateChanged') {
      this.handleEnterOrExitPhotoBrowser(wantParam);
    } else if (dataType === 'remoteReady') {
      if (this.onPickerControllerReady) {
        this.onPickerControllerReady();
        console.info('PhotoPickerComponent onReceive: onPickerControllerReady');
      }
    } else if (dataType === 'onPhotoBrowserChanged') {
      this.handlePhotoBrowserChange(wantParam);
    } else {
      console.info('PhotoPickerComponent onReceive: other case');
    }
    console.info('PhotoPickerComponent onReceive' + JSON.stringify(wantParam));
  }

  private handleSelectOrDeselect(wantParam: Record<string, Object>): void {
    let isSelect: boolean = wantParam['isSelect'] as boolean;
    if (isSelect) {
      if (this.onSelect) {
        this.onSelect(wantParam['select-item-list'] as string);
        console.info('PhotoPickerComponent onReceive: onSelect');
      }
    } else {
      if (this.onDeselect) {
        this.onDeselect(wantParam['select-item-list'] as string);
        console.info('PhotoPickerComponent onReceive: onDeselect');
      }
    }
  }

  private handleItemClick(wantParam: Record<string, Object>): void {
    if (this.onItemClicked) {
      let clickType: ClickType = ClickType.SELECTED;
      let type = wantParam['clickType'] as string;
      if (type === 'select') {
        clickType = ClickType.SELECTED;
      } else if (type === 'deselect') {
        clickType = ClickType.DESELECTED;
      } else {
        console.info('PhotoPickerComponent onReceive: other clickType');
      }
      let itemInfo: ItemInfo = new ItemInfo();
      let itemType: string = wantParam['itemType'] as string;
      if (itemType === 'thumbnail') {
        itemInfo.itemType = ItemType.THUMBNAIL;
      } else if (itemType === 'camera') {
        itemInfo.itemType = ItemType.CAMERA;
      } else {
        console.info('PhotoPickerComponent onReceive: other itemType');
      }
      itemInfo.uri = wantParam['uri'] as string;
      itemInfo.mimeType = wantParam['mimeType'] as string;
      itemInfo.width = wantParam['width'] as number;
      itemInfo.height = wantParam['height'] as number;
      itemInfo.size = wantParam['size'] as number;
      itemInfo.duration = wantParam['duration'] as number;
      let result: boolean = this.onItemClicked(itemInfo, clickType);
      console.info('PhotoPickerComponent onReceive: onItemClicked = ' + clickType);
      if (this.proxy) {
        if (itemType === 'thumbnail' && clickType === ClickType.SELECTED) {
          this.proxy.send({'clickConfirm': itemInfo.uri, 'isConfirm': result});
          console.info('PhotoPickerComponent onReceive: click confirm: uri = ' + itemInfo.uri + 'isConfirm = ' + result);
        }
        if (itemType === 'camera') {
          this.proxy.send({'enterCamera': result});
          console.info('PhotoPickerComponent onReceive: enter camera ' + result);
        }
      }
    }
  }

  private handleEnterOrExitPhotoBrowser(wantParam: Record<string, Object>): void {
    let isEnter: boolean = wantParam['isEnter'] as boolean;
    let photoBrowserInfo: PhotoBrowserInfo = new PhotoBrowserInfo();
    photoBrowserInfo.animatorParams = new AnimatorParams();
    photoBrowserInfo.animatorParams.duration = wantParam['duration'] as number;
    photoBrowserInfo.animatorParams.curve = wantParam['curve'] as Curve | ICurve | string;
    if (isEnter) {
      if (this.onEnterPhotoBrowser) {
        this.onEnterPhotoBrowser(photoBrowserInfo);
      }
    } else {
      if (this.onExitPhotoBrowser) {
        this.onExitPhotoBrowser(photoBrowserInfo);
      }
    }
    console.info('PhotoPickerComponent onReceive: onPhotoBrowserStateChanged = ' + isEnter);
  }

  private handlePhotoBrowserChange(wantParam: Record<string, Object>): void {
    let browserItemInfo: BaseItemInfo = new BaseItemInfo();
    browserItemInfo.uri = wantParam['uri'] as string;
    if (this.onPhotoBrowserChanged) {
      this.onPhotoBrowserChanged(browserItemInfo);
    }
    console.info('PhotoPickerComponent onReceive: onPhotoBrowserChanged = ' + browserItemInfo.uri);
  }

  private convertMIMETypeToFilterType(mimeType: photoAccessHelper.PhotoViewMIMETypes): string {
    let filterType: string;
    if (mimeType === photoAccessHelper.PhotoViewMIMETypes.IMAGE_TYPE) {
      filterType = FILTER_MEDIA_TYPE_IMAGE;
    } else if (mimeType === photoAccessHelper.PhotoViewMIMETypes.VIDEO_TYPE) {
      filterType = FILTER_MEDIA_TYPE_VIDEO;
    } else {
      filterType = FILTER_MEDIA_TYPE_ALL;
    }
    console.info('PhotoPickerComponent convertMIMETypeToFilterType' + JSON.stringify(filterType));
    return filterType;
  }
}

@Observed
export class PickerController {
  data?: Map<string, Array<string> | string | MaxSelected>;

  setData(type: DataType, data: Object) {
    if (!data) {
      return;
    }
    if (type === DataType.SET_SELECTED_URIS) {
      if (data instanceof Array) {
        let uriLists: Array<string> = data as Array<string>;
        if (uriLists) {
          this.data = new Map([['SET_SELECTED_URIS', [...uriLists]]]);
          console.info('PhotoPickerComponent SET_SELECTED_URIS' + JSON.stringify(uriLists));
        }
      }
    } else if (type === DataType.SET_ALBUM_URI) {
      let albumUri: string = data as string;
      if (albumUri) {
        this.data = new Map([['SET_ALBUM_URI', albumUri]]);
        console.info('PhotoPickerComponent SET_ALBUM_URI' + JSON.stringify(albumUri));
      }
    } else {
      console.info('PhotoPickerComponent setData: other case');
    }
  }

  setMaxSelected(maxSelected: MaxSelected) {
    if (maxSelected) {
      this.data = new Map([['SET_MAX_SELECT_COUNT', maxSelected]]);
      console.info('PhotoPickerComponent SET_MAX_SELECT_COUNT' + JSON.stringify(maxSelected));
    }
  }

  setPhotoBrowserItem(uri: string) {
    this.data = new Map([['SET_PHOTO_BROWSER_ITEM', uri]]);
    console.info('PhotoPickerComponent SET_PHOTO_BROWSER_ITEM' + JSON.stringify(uri));
  }
}

export class PickerOptions extends photoAccessHelper.BaseSelectOptions {
  checkBoxColor?: string;
  backgroundColor?: string;
  isRepeatSelectSupported?: boolean;
  checkboxTextColor?: string;
  photoBrowserBackgroundColorMode?: PickerColorMode;
  maxSelectedReminderMode?: ReminderMode;
  orientation?: PickerOrientation;
  selectMode?: SelectMode;
  maxPhotoSelectNumber?: number;
  maxVideoSelectNumber?: number;
}

export class BaseItemInfo {
  uri?: string;
  mimeType?: string;
  width?: number;
  height?: number;
  size?: number;
  duration?: number;
}

export class ItemInfo extends BaseItemInfo {
  itemType?: ItemType;
}

export class PhotoBrowserInfo {
  animatorParams?: AnimatorParams;
}

export class AnimatorParams {
  duration?: number;
  curve?: Curve | ICurve | string;
}

export class MaxSelected {
  data?: Map<MaxCountType, number>;
}

export enum DataType {
  SET_SELECTED_URIS = 1,
  SET_ALBUM_URI = 2
}

export enum ItemType {
  THUMBNAIL = 0,
  CAMERA = 1
}

export enum ClickType {
  SELECTED = 0,
  DESELECTED = 1
}

export enum PickerOrientation {
  VERTICAL = 0,
  HORIZONTAL = 1
}

export enum SelectMode {
  SINGLE_SELECT = 0,
  MULTI_SELECT = 1
}

export enum PickerColorMode {
  AUTO = 0,
  LIGHT = 1,
  DARK = 2
}

export enum ReminderMode {
  NONE = 0,
  TOAST = 1,
  MASK = 2
}

export enum MaxCountType {
  TOTAL_MAX_COUNT = 0,
  PHOTO_MAX_COUNT = 1,
  VIDEO_MAX_COUNT = 2
}