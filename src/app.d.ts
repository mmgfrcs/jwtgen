// See https://kit.svelte.dev/docs/types#app

import type { SvelteComponent } from "svelte";

// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

declare module "@svelte-plugins/datepicker" {
	interface DatePickerProps {
		/**
		 * Represents the start date for a date picker.
		 * @default null
		 */
		startDate?: any;
	  
		/**
		 * Represents the end date for a date picker.
		 * @default null
		 */
		endDate?: any;
	  
		/**
		 * Represents the start time for the date picker (in HH:mm format).
		 * @default '00:00'
		 */
		startDateTime?: string;
	  
		/**
		 * Represents the end time for the date picker (in HH:mm format).
		 * @default '00:00'
		 */
		endDateTime?: string;
	  
		/**
		 * Represents the current date.
		 */
		today?: Date;
	  
		/**
		 * Represents the default year for the date picker.
		 */
		defaultYear?: number;
	  
		/**
		 * Represents the default month for the date picker.
		 */
		defaultMonth?: number;
	  
		/**
		 * Represents the start day of the week (0 for Sunday, 1 for Monday, etc.).
		 */
		startOfWeek?: number;
	  
		/**
		 * Indicates whether the date picker has multiple panes.
		 */
		isMultipane?: boolean;
	  
		/**
		 * Indicates whether the date picker is in range mode.
		 */
		isRange?: boolean;
	  
		/**
		 * Indicates whether the date picker is open.
		 */
		isOpen?: boolean;
	  
		/**
		 * Specifies the alignment of the date picker (e.g., 'left', 'center', 'right').
		 */
		align?: string;
	  
		/**
		 * Represents the theme of the date picker.
		 */
		theme?: string;
	  
		/**
		 * An array of disabled dates.
		 */
		disabledDates?: string[];
	  
		/**
		 * An array of enabled dates.
		 */
		enabledDates?: string[];
	  
		/**
		 * Callback function to handle day click events.
		 */
		onDayClick?: (event: any) => void;
	  
		/**
		 * Callback function to handle the navigation click event for months and years
		 */
		onNavigationChange?: (event: any) => void;
	  
		/**
		 * Indicates whether the date picker should always be shown.
		 */
		alwaysShow?: boolean;
	  
		/**
		 * Indicates whether year controls are displayed in the date picker.
		 */
		showYearControls?: boolean;
	  
		/**
		 * Indicates whether preset options are displayed in the date picker.
		 */
		showPresets?: boolean;
	  
		/**
		 * Indicates whether the time picker is shown in the date picker.
		 */
		showTimePicker?: boolean;
	  
		/**
		 * Indicates whether future dates are enabled.
		 */
		enableFutureDates?: boolean;
	  
		/**
		 * Indicates whether past dates are enabled.
		 */
		enablePastDates?: boolean;
	  
		/**
		 * An array of preset date range labels.
		 */
		presetLabels?: string[];
	  
		/**
		 * An array of preset date ranges with labels and start/end timestamps.
		 */
		presetRanges?: Object[];
	  
		/**
		 * An array of day-of-week labels.
		 */
		dowLabels?: string[];
	  
		/**
		 * An array of month labels.
		 */
		monthLabels?: string[];
	  
		/**
		 * Determines if the default font "Rubik" should be loaded.
		 */
		includeFont?: boolean;
	  }
	export class DatePicker extends SvelteComponent<DatePickerProps> {}
}


export {};
