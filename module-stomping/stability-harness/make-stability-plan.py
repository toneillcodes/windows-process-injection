import argparse
import csv
import json
import sys

STOMP_PATH = "C:\\Users\\Administrator\\Desktop\\git\\windows-process-injection\\module-stomping\\remote-stomp.exe"
TIMEOUT = 60

def transform_data(csv_file_path, json_file_path):
    transformed_data = []

    try:
        with open(csv_file_path, mode="r", encoding="utf-8") as csv_file:
            csv_reader = csv.DictReader(csv_file)

            # TargetProcess,Name,TextSectionSize
            for row in csv_reader:
                targetProcess = row.get("TargetProcess", "").strip()
                targetModule = row.get("Name", "").strip()
                targetSectionSize = row.get("TextSectionSize", "").strip()

                if not targetModule.endswith(".exe"):
                    json_entry = {
                        "target_executable": targetProcess,
                        "trigger_dll": targetModule,
                        "secondary_tool": STOMP_PATH,
                        "tool_arguments": ["-p", "{pid}", "-d", targetModule, "-n", "-s", targetSectionSize],
                        "timeout_seconds": TIMEOUT,
                    }

                    transformed_data.append(json_entry)

        with open(json_file_path, mode="w", encoding="utf-8") as json_file:
            json.dump(transformed_data, json_file, indent=2)

        print(f"Success! Processed {len(transformed_data)} rows.")
        print(f"Input:  {csv_file_path}")
        print(f"Output: {json_file_path}")

    except FileNotFoundError:
        print(f"Error: The file '{csv_file_path}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Transform a CSV file into a specific JSON structure."
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to the input CSV file (must contain field2 and field3 headers).",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Path where the output JSON file should be saved.",
    )

    # Parse the arguments from the command line
    args = parser.parse_args()

    # Run the transformation logic
    transform_data(args.input, args.output)