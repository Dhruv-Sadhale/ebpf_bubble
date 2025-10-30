#!/usr/bin/env python3

import re
import subprocess
import pymysql
from pymysql import Error

# Database configuration for MySQL
DB_CONFIG = {
    'database': 'ebpf',  # Your database name
    'user': 'root',                 # Your MySQL username
    'password': 'DHRmin24$',    # Your MySQL password
    'host': 'localhost',
    'port': 3306
}

def create_tables(conn):
    """Create the necessary tables if they don't exist"""
    cursor = conn.cursor()
    
    # Create tcpreplay table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tcpreplay (
            sr_no INT AUTO_INCREMENT PRIMARY KEY,
            successful_packets INT,
            pps DECIMAL(12, 2)
        )
    """)
    
    # Create sketch_output table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bubble_sketch (
            sr_no INT AUTO_INCREMENT PRIMARY KEY,
            bucket_num INT,
            threshold1 INT,
            lossy_func_id INT,
            k INT,
            f_max INT,
            precision_score DECIMAL(5, 2),
            recall DECIMAL(5, 2),
            f1_score DECIMAL(5, 2),
            avg_abs_error DECIMAL(10, 2),
            avg_rel_error DECIMAL(5, 2)
        )
    """)
    
    conn.commit()
    cursor.close()
    print("Tables created successfully!")

def parse_tcpreplay(filename):
    """Parse tcpreplay_output.txt and extract successful packets and pps"""
    entries = []
    
    with open(filename, 'r') as f:
        content = f.read()
    
    # Split by "Actual:" to get individual entries
    blocks = content.split('Actual:')[1:]  # Skip the first empty split
    
    for block in blocks:
        # Extract pps from Rated line
        pps_match = re.search(r'Rated:.*?(\d+\.\d+)\s+pps', block)
        # Extract successful packets
        packets_match = re.search(r'Successful packets:\s+(\d+)', block)
        
        if pps_match and packets_match:
            pps = float(pps_match.group(1))
            packets = int(packets_match.group(1))
            entries.append((packets, pps))
    
    return entries

def parse_sketch_output(filename):
    """Parse sketch_output.txt and extract configuration parameters"""
    with open(filename, 'r') as f:
        content = f.read()
    
    # Extract parameters
    bucket_num = int(re.search(r'bucket_num=(\d+)', content).group(1))
    threshold1 = int(re.search(r'threshold1=(\d+)', content).group(1))
    lossy_func_id = 1
    k = int(re.search(r'K=(\d+)', content).group(1))
    f_max = int(re.search(r'f_max=(\d+)', content).group(1))
    
    return {
        'bucket_num': bucket_num,
        'threshold1': threshold1,
        'lossy_func_id': lossy_func_id,
        'k': k,
        'f_max': f_max
    }

def parse_accuracy_calc(filename):
    """Parse accuracy_calc.txt and extract metrics"""
    with open(filename, 'r') as f:
        content = f.read()
    
    # Extract metrics
    precision_match = re.search(r'Precision:\s+([\d.]+)%', content)
    recall_match = re.search(r'Recall:\s+([\d.]+)%', content)
    f1_match = re.search(r'F1-Score:\s+([\d.]+)%', content)
    abs_error_match = re.search(r'Average absolute error:\s+([\d.]+)\s+packets', content)
    rel_error_match = re.search(r'Average relative error:\s+([\d.]+)%', content)
    
    return {
        'precision': float(precision_match.group(1)) if precision_match else None,
        'recall': float(recall_match.group(1)) if recall_match else None,
        'f1_score': float(f1_match.group(1)) if f1_match else None,
        'avg_abs_error': float(abs_error_match.group(1)) if abs_error_match else None,
        'avg_rel_error': float(rel_error_match.group(1)) if rel_error_match else None
    }

def run_accuracy_calculations():
    """Run accuracy_calc.py for top 10, 100, and 1000"""
    top_values = [1000]
    results = {}
    
    for top in top_values:
        print(f"Running accuracy calculation for top {top}...")
        cmd = f"python3 accuracy_calc.py --sketch sketch_output.txt --pcap ./1.pcap --top {top} > accuracy_calc.txt"
        subprocess.run(cmd, shell=True, check=True)
        
        # Parse the output
        metrics = parse_accuracy_calc('accuracy_calc.txt')
        top=1000
        results[f'top{top}'] = metrics
        print(f"  Precision: {metrics['precision']}%, Recall: {metrics['recall']}%")
    
    return results

def insert_data(conn):
    """Insert parsed data into database"""
    cursor = conn.cursor()
    
    # Parse tcpreplay data
    print("\nParsing tcpreplay_output.txt...")
    tcpreplay_entries = parse_tcpreplay('tcpreplay_output.txt')
    print(f"Found {len(tcpreplay_entries)} tcpreplay entries")
    
    # Parse sketch output
    print("Parsing sketch_output.txt...")
    sketch_params = parse_sketch_output('sketch_output.txt')
    print(f"Extracted sketch parameters: {sketch_params}")
    
    # Run accuracy calculations
    print("\nRunning accuracy calculations...")
    accuracy_results = run_accuracy_calculations()
    
    # Insert tcpreplay data
    print("\nInserting tcpreplay data...")
    for packets, pps in tcpreplay_entries:
        cursor.execute("""
            INSERT INTO tcpreplay (successful_packets, pps)
            VALUES (%s, %s)
        """, (packets, pps))
    
    # Insert sketch data with accuracy metrics
    print("Inserting sketch data with accuracy metrics...")
    cursor.execute("""
        INSERT INTO bubble_sketch (
            bucket_num, threshold1, lossy_func_id, k, f_max,
            precision_score, recall, f1_score, 
            avg_abs_error, avg_rel_error  
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        sketch_params['bucket_num'],
        sketch_params['threshold1'],
        sketch_params['lossy_func_id'],
        sketch_params['k'],
        sketch_params['f_max'],
        accuracy_results['top1000']['precision'],
        accuracy_results['top1000']['recall'],
        accuracy_results['top1000']['f1_score'],
        accuracy_results['top1000']['avg_abs_error'],
        accuracy_results['top1000']['avg_rel_error']
    ))
    
    conn.commit()
    cursor.close()
    print("Data inserted successfully!")


def main():
    """Main execution function"""
    try:
        # Connect to database
        print("Connecting to database...")
        conn = pymysql.connect(**DB_CONFIG)
        
        print("Successfully connected to MySQL database")
        
        # Create tables
        create_tables(conn)
        
        # Insert data
        insert_data(conn)
        
        # Show combined table
        
        conn.close()
        print("Script completed successfully!")
        
    except Error as e:
        print(f"MySQL Error: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
